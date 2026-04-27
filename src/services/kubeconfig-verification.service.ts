import * as k8s from '@kubernetes/client-node'

/**
 * Result of kubeconfig verification
 */
export interface KubeconfigVerificationResult {
  success: boolean
  cluster: {
    name: string
    server: string
    version?: string
  } | null
  user: {
    name: string
    authMethod: 'token' | 'client-certificate' | 'exec' | 'auth-provider' | 'unknown'
  } | null
  identity: {
    username: string
    groups: string[]
    uid?: string
  } | null
  permissions: {
    canListNamespaces: boolean
    canListPods: boolean
    canCreateJobs: boolean
    canListSecrets: boolean
    namespaces?: string[]
  } | null
  error?: string
}

/**
 * Service for verifying kubeconfig and retrieving token permissions
 * Makes REAL API calls to validate the configuration
 */
export class KubeconfigVerificationService {
  /**
   * Verify a kubeconfig string and retrieve identity/permissions
   * This makes actual API calls to the Kubernetes cluster
   */
  async verify(kubeconfigYaml: string): Promise<KubeconfigVerificationResult> {
    let kc: k8s.KubeConfig

    // Step 1: Parse kubeconfig
    try {
      kc = new k8s.KubeConfig()
      kc.loadFromString(kubeconfigYaml)
    } catch (error) {
      return {
        success: false,
        cluster: null,
        user: null,
        identity: null,
        permissions: null,
        error: `Invalid kubeconfig format: ${error instanceof Error ? error.message : 'unknown error'}`,
      }
    }

    // Step 2: Get context info
    const currentContext = kc.getCurrentContext()
    const context = kc.getContextObject(currentContext)

    if (!context) {
      return {
        success: false,
        cluster: null,
        user: null,
        identity: null,
        permissions: null,
        error: 'No valid context found in kubeconfig',
      }
    }

    const clusterObj = kc.getCluster(context.cluster)
    const userObj = kc.getUser(context.user)

    if (!clusterObj) {
      return {
        success: false,
        cluster: null,
        user: null,
        identity: null,
        permissions: null,
        error: `Cluster "${context.cluster}" not found in kubeconfig`,
      }
    }

    // Build basic info (before validation)
    const authMethod = this.detectAuthMethod(userObj)
    const userInfo = userObj
      ? {
          name: userObj.name,
          authMethod,
        }
      : null

    // Step 3: REAL CONNECTION TEST - Try to get cluster version
    let clusterVersion: string | undefined
    try {
      const versionApi = kc.makeApiClient(k8s.VersionApi)
      const versionResponse = await versionApi.getCode()
      clusterVersion = versionResponse.gitVersion
    } catch (error) {
      const errorMessage = this.extractErrorMessage(error)
      return {
        success: false,
        cluster: {
          name: clusterObj.name,
          server: clusterObj.server,
        },
        user: userInfo,
        identity: null,
        permissions: null,
        error: `Failed to connect to cluster: ${errorMessage}`,
      }
    }

    const clusterInfo = {
      name: clusterObj.name,
      server: clusterObj.server,
      version: clusterVersion,
    }

    // Step 4: Get identity via SelfSubjectReview (real API call)
    const identity = await this.getIdentity(kc)

    // Step 5: Check permissions via SelfSubjectAccessReview (real API calls)
    const permissions = await this.checkPermissions(kc)

    return {
      success: true,
      cluster: clusterInfo,
      user: userInfo,
      identity,
      permissions,
    }
  }

  /**
   * Extract a meaningful error message from Kubernetes API errors
   */
  private extractErrorMessage(error: unknown): string {
    if (error instanceof Error) {
      // Check for network errors
      if (error.message.includes('ECONNREFUSED')) {
        return 'Connection refused - cluster is unreachable'
      }
      if (error.message.includes('ENOTFOUND')) {
        return 'DNS resolution failed - cluster hostname not found'
      }
      if (error.message.includes('ETIMEDOUT')) {
        return 'Connection timed out - cluster is unreachable'
      }
      if (error.message.includes('certificate')) {
        return 'Certificate error - invalid or untrusted certificate'
      }

      // Check for HTTP errors from k8s client
      const httpError = error as any
      if (httpError.response?.statusCode === 401) {
        return 'Authentication failed - invalid or expired token'
      }
      if (httpError.response?.statusCode === 403) {
        return 'Authorization failed - insufficient permissions'
      }
      if (httpError.body?.message) {
        return httpError.body.message
      }

      return error.message
    }
    return 'Unknown error'
  }

  /**
   * Detect the authentication method used in the kubeconfig
   */
  private detectAuthMethod(
    user: k8s.User | null
  ): 'token' | 'client-certificate' | 'exec' | 'auth-provider' | 'unknown' {
    if (!user) return 'unknown'

    if (user.token) return 'token'
    if (user.certData || user.certFile) return 'client-certificate'
    if (user.exec) return 'exec'
    if (user.authProvider) return 'auth-provider'

    return 'unknown'
  }

  /**
   * Get the identity of the current user via SelfSubjectReview
   * This makes a REAL API call to the cluster
   */
  private async getIdentity(
    kc: k8s.KubeConfig
  ): Promise<KubeconfigVerificationResult['identity']> {
    try {
      const authApi = kc.makeApiClient(k8s.AuthenticationV1Api)

      // Use SelfSubjectReview to get current user info
      const review: k8s.V1SelfSubjectReview = {
        apiVersion: 'authentication.k8s.io/v1',
        kind: 'SelfSubjectReview',
      }

      const response = await authApi.createSelfSubjectReview({ body: review })
      const userInfo = response.status?.userInfo

      if (userInfo) {
        return {
          username: userInfo.username || 'unknown',
          groups: userInfo.groups || [],
          uid: userInfo.uid,
        }
      }

      return null
    } catch (error) {
      // SelfSubjectReview might not be available on older clusters (< 1.28)
      // Fall back to null but don't fail the whole verification
      console.warn(
        'SelfSubjectReview not available:',
        error instanceof Error ? error.message : error
      )
      return null
    }
  }

  /**
   * Check permissions using SelfSubjectAccessReview
   * Also tries to list namespaces to get actual accessible namespaces
   * All calls are REAL API calls to the cluster
   */
  private async checkPermissions(
    kc: k8s.KubeConfig
  ): Promise<KubeconfigVerificationResult['permissions']> {
    const authApi = kc.makeApiClient(k8s.AuthorizationV1Api)
    const coreApi = kc.makeApiClient(k8s.CoreV1Api)

    // Check specific permissions via SelfSubjectAccessReview
    const [canListNamespaces, canListPods, canCreateJobs, canListSecrets] =
      await Promise.all([
        this.checkAccess(authApi, '', 'namespaces', 'list'),
        this.checkAccess(authApi, '', 'pods', 'list'),
        this.checkAccess(authApi, '', 'jobs', 'create', 'batch'),
        this.checkAccess(authApi, '', 'secrets', 'list'),
      ])

    // Try to actually list namespaces to get real data
    let namespaces: string[] | undefined
    if (canListNamespaces) {
      try {
        const nsResponse = await coreApi.listNamespace()
        namespaces = nsResponse.items.map((ns) => ns.metadata?.name || '').filter(Boolean)
      } catch {
        // If listing fails despite having permission, just skip
      }
    }

    return {
      canListNamespaces,
      canListPods,
      canCreateJobs,
      canListSecrets,
      namespaces,
    }
  }

  /**
   * Check if user can perform a specific action using SelfSubjectAccessReview
   * This is a REAL API call that asks the cluster if the current user has permission
   */
  private async checkAccess(
    authApi: k8s.AuthorizationV1Api,
    namespace: string,
    resource: string,
    verb: string,
    group?: string
  ): Promise<boolean> {
    try {
      const review: k8s.V1SelfSubjectAccessReview = {
        apiVersion: 'authorization.k8s.io/v1',
        kind: 'SelfSubjectAccessReview',
        spec: {
          resourceAttributes: {
            namespace: namespace || undefined,
            verb,
            resource,
            group: group || '',
          },
        },
      }

      const response = await authApi.createSelfSubjectAccessReview({ body: review })
      return response.status?.allowed === true
    } catch (error) {
      console.warn(
        `Failed to check access for ${verb} ${resource}:`,
        error instanceof Error ? error.message : error
      )
      return false
    }
  }
}

export const kubeconfigVerificationService = new KubeconfigVerificationService()
