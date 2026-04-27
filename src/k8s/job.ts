import * as k8s from '@kubernetes/client-node'
import { V1JobStatus } from '@kubernetes/client-node'
import Mustache from 'mustache'
import moment from 'moment'
import { getKubeConfig, getSource, K8sApiError } from './config.js'
import { createOrReplaceConfigMap } from './configmap.js'
import { jobTemplate, sourceTemplate } from './template.js'
import type { DatabaseSelected, JobInfo } from '../schemas/job.schema.js'

export async function createJob(
    database_type: string,
    action: string,
    cluster: string,
    date: Date,
    bases: DatabaseSelected[]
): Promise<true | string> {
    try {
        const job = structuredClone(jobTemplate[action][database_type])
        if (
            !job?.spec?.template?.spec?.containers.length ||
            !job?.spec?.template?.spec?.containers[0]?.env?.length ||
            !job.metadata ||
            !job.spec.template.metadata
        ) {
            return 'Job template is incomplete or missing'
        }

        const date_name = new Date()
            .toJSON()
            .slice(0, 19)
            .replace('T', '')
            .replaceAll('-', '')
            .replaceAll(':', '')
        job.metadata.name = `${action}-${database_type}-${date_name}`

        let sourceYamlTemplate, image
        try {
            sourceYamlTemplate = await getSource(
                cluster,
                database_type,
                'sourceYamlTemplate'
            )
            image = await getSource(cluster, database_type, 'image')
        } catch (e: unknown) {
            const err = e as Error
            return `Error fetching source or image: ${err?.message || e}`
        }

        // Fill source template with values
        const source = structuredClone(sourceTemplate)
        source.metadata.name = `source-${database_type}-${date_name}`
        if (
            job.spec &&
            job.spec.template.spec.volumes &&
            job.spec.template.spec.volumes[0] &&
            job.spec.template.spec.volumes[0].configMap
        ) {
            job.spec.template.spec.volumes[0].configMap.name = `source-${database_type}-${date_name}`
        }
        source.data['source.yaml'] = Mustache.render(sourceYamlTemplate, {
            bases,
        })
        const configMapOk = await createOrReplaceConfigMap(
            cluster,
            'default',
            source
        )
        if (!configMapOk) return 'Failed to create or update ConfigMap'

        const dateFormat = (d: Date) =>
            d.toJSON().slice(0, 19).replace('T', '_').replaceAll(':', '-')
        job.spec.template.spec.containers[0].env[3].value = dateFormat(date)
        job.spec.template.spec.containers[0].env[4].value = dateFormat(date)
        job.spec.template.metadata.labels = {
            timestamp: dateFormat(date),
            action: action,
            'database/type': `${database_type}`,
            cluster: `${cluster}`,
            'operator/name': 'kuma',
        }
        job.spec.template.spec.containers[0].image = image

        // --- Create/replace Job in K8s ---
        // Compose K8s client from config
        let kubeConfigStr
        try {
            kubeConfigStr = await getKubeConfig(cluster)
        } catch (e: unknown) {
            const err = e as Error
            return `Error fetching KubeConfig: ${err?.message || e}`
        }
        const kc = new k8s.KubeConfig()
        kc.loadFromString(kubeConfigStr)
        const api = kc.makeApiClient(k8s.BatchV1Api)
        try {
            await api.readNamespacedJob({ name: job.metadata.name, namespace: 'default' })
            try {
                await api.deleteNamespacedJob({ name: job.metadata.name, namespace: 'default' })
            } catch {
                // Ignore delete errors
            }
        } catch (e: unknown) {
            const err = e as K8sApiError
            if (!err?.response || err.response.statusCode !== 404) {
                return `Error reading job: ${err?.message || e}`
            }
        }
        try {
            await api.createNamespacedJob({ namespace: 'default', body: job })
        } catch (e: unknown) {
            const err = e as { body?: { message?: string }; message?: string }
            return `Error creating job: ${err?.body?.message || err?.message || e}`
        }

        return true
    } catch (e: unknown) {
        const err = e as Error
        console.error('createJob error:', e)
        return err?.message || 'Unknown error'
    }
}

async function getPods(
    namespace: string,
    labelSelector: string,
    cluster: string
): Promise<k8s.V1Pod[]> {
    const kubeConfigString = await getKubeConfig(cluster)
    const kc = new k8s.KubeConfig()
    kc.loadFromString(kubeConfigString)
    const api = kc.makeApiClient(k8s.CoreV1Api)

    try {
        const response = await api.listNamespacedPod({
            namespace,
            labelSelector,
        })
        return response.items
    } catch (error) {
        console.error('Error fetching job pods:', error)
        throw error
    }
}

async function getJobs(
    namespace: string,
    cluster: string
): Promise<k8s.V1Job[]> {
    const labelSelector = 'operator/name=kuma,database/type,timestamp'
    const kubeConfigString = await getKubeConfig(cluster)
    const kc = new k8s.KubeConfig()
    kc.loadFromString(kubeConfigString)
    const api = kc.makeApiClient(k8s.BatchV1Api)

    try {
        const response = await api.listNamespacedJob({
            namespace,
            labelSelector,
        })
        return response.items
    } catch (error) {
        console.error('Error fetching jobs:', error)
        throw error
    }
}

export async function getBackupPods(namespace: string, cluster: string) {
    const labelSelector = 'operator/name=kuma,database/type,timestamp'

    return await getPods(namespace, labelSelector, cluster)
}

function getJobStatus(status: V1JobStatus): string {
    if (!status || !status.conditions) return 'Unknown'
    const conditions = status.conditions

    if (!conditions || !Array.isArray(conditions)) return 'Unknown'

    // Find the most recent status condition
    const statusCondition = conditions
        .sort((a, b) => {
            if (!b.lastTransitionTime || !a.lastTransitionTime) return 0
            return (
                new Date(b.lastTransitionTime).getTime() -
                new Date(a.lastTransitionTime).getTime()
            )
        })
        .find(
            (condition) =>
                condition.type === 'Complete' || condition.type === 'Failed'
        )

    if (!statusCondition) return 'pending'

    if (
        statusCondition.type === 'Complete' &&
        statusCondition.status === 'True'
    ) {
        return 'completed'
    }
    if (
        statusCondition.type === 'Failed' &&
        statusCondition.status === 'True'
    ) {
        return 'failed'
    }

    return 'running'
}

export async function getJobsInfo(
    namespace: string,
    cluster: string
): Promise<JobInfo[]> {
    try {
        const jobs = await getJobs(namespace, cluster)

        return jobs
            .map((job): JobInfo | null => {
                if (
                    !job.metadata ||
                    !job.metadata.labels ||
                    !job.status ||
                    !job.status.conditions ||
                    !job.metadata.creationTimestamp
                ) {
                    return null
                }

                const creationTimestamp = moment(job.metadata.creationTimestamp)
                const age = creationTimestamp.fromNow(true)

                return {
                    database_type:
                        job.metadata.labels['database/type'] || 'N/A',
                    name: job.metadata.name || 'N/A',
                    timestamp: job.metadata.labels['timestamp'] || 'N/A',
                    status: getJobStatus(job.status) as JobInfo['status'],
                    age,
                    namespace: job.metadata.namespace || 'N/A',
                    creationTimestamp: job.metadata.creationTimestamp,
                }
            })
            .filter((info): info is JobInfo => info !== null)
            .sort((a, b) => {
                return (
                    moment(b.creationTimestamp).valueOf() -
                    moment(a.creationTimestamp).valueOf()
                )
            })
    } catch (error) {
        console.error('Error in getJobsInfo:', error)
        throw error
    }
}
