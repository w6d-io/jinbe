import * as k8s from '@kubernetes/client-node'
import { getKubeConfig, K8sApiError } from './config.js'

export async function createOrReplaceConfigMap(
    cluster: string,
    namespace: string,
    manifest: k8s.V1ConfigMap
): Promise<boolean> {
    if (!manifest.metadata || !manifest.metadata.name) return false
    const kubeConfigString = await getKubeConfig(cluster)
    const kc = new k8s.KubeConfig()
    kc.loadFromString(kubeConfigString)
    const k8sCoreApi = kc.makeApiClient(k8s.CoreV1Api)
    try {
        // Attempt to get the ConfigMap
        await k8sCoreApi.readNamespacedConfigMap({
            name: manifest.metadata.name,
            namespace,
        })

        // If the ConfigMap exists, replace it
        await k8sCoreApi.replaceNamespacedConfigMap({
            name: manifest.metadata.name,
            namespace,
            body: manifest,
        })
        console.log(`ConfigMap ${manifest.metadata.name} replaced`)
    } catch (e) {
        const error = e as K8sApiError
        if (error.response && error.response.statusCode === 404) {
            await k8sCoreApi.createNamespacedConfigMap({
                namespace,
                body: manifest,
            })
            console.log(`ConfigMap ${manifest.metadata.name} created`)
        } else {
            // Some other error occurred
            console.error(`Error: ${error.message}`)
            return false
        }
    }
    return true
}
