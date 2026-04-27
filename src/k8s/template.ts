import * as k8s from '@kubernetes/client-node'

const jobRestoreMongoTemplate: k8s.V1Job = {
    metadata: {
        name: 'restore',
    },
    spec: {
        backoffLimit: 1,
        completions: 1,
        parallelism: 1,
        template: {
            metadata: {
                annotations: {
                    'vault.security.banzaicloud.io/vault-addr':
                    'http://vault.vault:8200',
                    'vault.security.banzaicloud.io/vault-role': 'mongo',
                    'vault.security.banzaicloud.io/vault-skip-verify': 'true',
                },
            },
            spec: {
                restartPolicy: 'Never',
                serviceAccountName: 'kuma',
                containers: [
                    {
                        name: 'restore',
                        command: [
                            '/bin/bash',
                            '-c',
                            'echo source /app/mongo.sh && mongo_restore',
                        ],
                        env: [
                            {
                                name: 'GCP_BUCKET_NAME',
                                value: 'vault:strada/data/backup-tool/common#GCP_BUCKET_NAME',
                            },
                            {
                                name: 'GCP_PROJECT_ID',
                                value: 'k8s-w6d-qa',
                            },
                            {
                                name: 'yamlFile',
                                value: '/config/source.yaml',
                            },
                            {
                                name: 'timeStamp',
                                value: '',
                            },
                            {
                                name: 'TIMESTAMP',
                                value: '',
                            },
                            {
                                name: 'MONGO_URI',
                                value: 'vault:strada/data/backup-tool/mongo#MONGO_URI',
                            },
                        ],
                        image: '',
                        imagePullPolicy: 'Always',
                        resources: {},
                    },
                ],
            },
        },
    },
}

const jobBackupMongoTemplate: k8s.V1Job = {
    metadata: {
        name: 'restore',
    },
    spec: {
        backoffLimit: 0,
        completions: 1,
        parallelism: 1,
        template: {
            metadata: {
                annotations: {
                    'vault.security.banzaicloud.io/vault-addr':
                        'http://vault.vault:8200',
                    'vault.security.banzaicloud.io/vault-role': 'mongo',
                    'vault.security.banzaicloud.io/vault-skip-verify': 'true',
                },
            },
            spec: {
                restartPolicy: 'Never',
                serviceAccountName: 'kuma',
                containers: [
                    {
                        name: 'restore',
                        command: [
                            '/bin/bash',
                            '-c',
                            'echo source /app/mongo.sh && mongo_backup',
                        ],
                        env: [
                            {
                                name: 'GCP_BUCKET_NAME',
                                value: 'vault:strada/data/backup-tool/common#GCP_BUCKET_NAME',
                            },
                            {
                                name: 'GCP_PROJECT_ID',
                                value: 'k8s-w6d-qa',
                            },
                            {
                                name: 'yamlFile',
                                value: '/config/source.yaml',
                            },
                            {
                                name: 'timeStamp',
                                value: '',
                            },
                            {
                                name: 'TIMESTAMP',
                                value: '',
                            },
                            {
                                name: 'MONGO_URI',
                                value: 'vault:strada/data/backup-tool/mongo#MONGO_URI',
                            },
                        ],
                        image: '',
                        imagePullPolicy: 'Always',
                        resources: {},
                    },
                ],
            },
        },
    },
}

const jobRestorePostgresTemplate: k8s.V1Job = {
    metadata: {
        generateName: 'restore',
    },
    spec: {
        backoffLimit: 1,
        completions: 1,
        parallelism: 1,
        template: {
            metadata: {
                annotations: {
                    'vault.security.banzaicloud.io/vault-addr':
                        'http://vault.vault:8200',
                    'vault.security.banzaicloud.io/vault-role': 'postgres',
                    'vault.security.banzaicloud.io/vault-skip-verify': 'true',
                },
            },
            spec: {
                restartPolicy: 'Never',
                serviceAccountName: 'kuma',
                containers: [
                    {
                        name: 'restore',
                        command: [
                            '/bin/bash',
                            '-c',
                            'source /app/postgres.sh && postgres_restore',
                        ],
                        env: [
                            {
                                name: 'GCP_BUCKET_NAME',
                                value: 'vault:strada/data/backup-tool/common#GCP_BUCKET_NAME',
                            },
                            {
                                name: 'GCP_PROJECT_ID',
                                value: 'k8s-w6d-qa',
                            },
                            {
                                name: 'yamlFile',
                                value: '/config/source.yaml',
                            },
                            {
                                name: 'timeStamp',
                                value: '',
                            },
                            {
                                name: 'TIMESTAMP',
                                value: '',
                            },
                            {
                                name: 'PGHOST',
                                value: 'vault:strada/data/backup-tool/postgres#PGHOST',
                            },
                            {
                                name: 'PGPASSWORD',
                                value: 'vault:strada/data/backup-tool/postgres#PGPASSWORD',
                            },
                        ],
                        image: '',
                        imagePullPolicy: 'Always',
                        resources: {},
                        volumeMounts: [
                            {
                                name: 'config',
                                mountPath: '/config',
                            },
                        ],
                    },
                ],
                volumes: [
                    {
                        name: 'config',
                        configMap: {
                            defaultMode: 0o444,
                            name: '',
                        },
                    },
                ],
            },
        },
    },
}

const jobBackupPostgresTemplate: k8s.V1Job = {
    metadata: {
        generateName: 'restore',
    },
    spec: {
        backoffLimit: 1,
        completions: 1,
        parallelism: 1,
        template: {
            metadata: {
                annotations: {
                    'vault.security.banzaicloud.io/vault-addr':
                        'http://vault.vault:8200',
                    'vault.security.banzaicloud.io/vault-role': 'postgres',
                    'vault.security.banzaicloud.io/vault-skip-verify': 'true',
                },
            },
            spec: {
                restartPolicy: 'Never',
                serviceAccountName: 'kuma',
                containers: [
                    {
                        name: 'restore',
                        command: [
                            '/bin/bash',
                            '-c',
                            'source /app/postgres.sh && postgres_backup',
                        ],
                        env: [
                            {
                                name: 'GCP_BUCKET_NAME',
                                value: 'vault:strada/data/backup-tool/common#GCP_BUCKET_NAME',
                            },
                            {
                                name: 'GCP_PROJECT_ID',
                                value: 'k8s-w6d-qa',
                            },
                            {
                                name: 'yamlFile',
                                value: '/config/source.yaml',
                            },
                            {
                                name: 'timeStamp',
                                value: '',
                            },
                            {
                                name: 'TIMESTAMP',
                                value: '',
                            },
                            {
                                name: 'PGHOST',
                                value: 'vault:strada/data/backup-tool/postgres#PGHOST',
                            },
                            {
                                name: 'PGPASSWORD',
                                value: 'vault:strada/data/backup-tool/postgres#PGPASSWORD',
                            },
                        ],
                        image: '',
                        imagePullPolicy: 'Always',
                        resources: {},
                        volumeMounts: [
                            {
                                name: 'config',
                                mountPath: '/config',
                            },
                        ],
                    },
                ],
                volumes: [
                    {
                        name: 'config',
                        configMap: {
                            defaultMode: 0o444,
                            name: '',
                        },
                    },
                ],
            },
        },
    },
}

export const jobRestoreTemplate: { [key: string]: k8s.V1Job } = {
    mongodb: jobRestoreMongoTemplate,
    postgresql: jobRestorePostgresTemplate,
}

const jobBackupTemplate: { [key: string]: k8s.V1Job } = {
    mongodb: jobBackupMongoTemplate,
    postgresql: jobBackupPostgresTemplate,
}

export const jobTemplate: { [key: string]: { [key: string]: k8s.V1Job } } = {
    restore: jobRestoreTemplate,
    backup: jobBackupTemplate,
}

export const sourceTemplate = {
    metadata: {
        name: 'source',
    },
    data: {
        'source.yaml': '',
    },
}
