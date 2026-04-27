# Documentation du Flow de Backup - Jinbe API

## Vue d'ensemble

L'API Jinbe gère des backups de bases de données organisés hiérarchiquement:
- Un **Cluster** contient plusieurs **Databases** et **Backups**
- Un **Backup** contient plusieurs **BackupItems** (une entrée par base de données sauvegardée)

---

## Modèle de Données (Prisma/MongoDB)

### Schéma des entités

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│   Cluster   │──1:N──│   Backup    │──1:N──│ BackupItem  │
└─────────────┘       └─────────────┘       └─────────────┘
       │
       │ 1:N
       ▼
┌─────────────┐       ┌─────────────┐
│  Database   │──1:1──│ DatabaseAPI │
└─────────────┘       └─────────────┘
```

### Modèle Backup

```prisma
model Backup {
  id            String       @id @default(auto()) @map("_id") @db.ObjectId
  database_type String       // Type de BDD (postgresql, mongodb, influxdb)
  date          DateTime     // Date du backup
  size          String       // Taille totale du backup
  clusterId     String       @db.ObjectId
  cluster       Cluster      @relation(fields: [clusterId], references: [id])
  BackupItem    BackupItem[] // Liste des BDD sauvegardées

  @@unique([database_type, date])
}
```

### Modèle BackupItem

```prisma
model BackupItem {
  id             String   @id @default(auto()) @map("_id") @db.ObjectId
  database_type  String   // Type de BDD
  name           String   // Nom de la base de données sauvegardée
  admin_username String   // Compte admin utilisé pour le backup
  username       String   // Propriétaire de la BDD
  filename       String   // Nom du fichier de backup
  date           DateTime // Date du backup
  backupId       String   @db.ObjectId
  backup         Backup   @relation(fields: [backupId], references: [id])
}
```

---

## Routes API et leur utilisation

### Backups

| Méthode | Route | Description |
|---------|-------|-------------|
| `GET` | `/api/backups` | Liste tous les backups (filtrable par `?clusterId=xxx`) |
| `GET` | `/api/backups/:id` | Récupère un backup avec ses BackupItems |
| `POST` | `/api/clusters/:clusterId/backups` | Crée un backup sous un cluster |
| `DELETE` | `/api/backups/:id` | Supprime un backup et ses BackupItems |

### BackupItems

| Méthode | Route | Description |
|---------|-------|-------------|
| `GET` | `/api/backup-items` | Liste tous les backup items (filtrable par `?backupId=xxx`) |
| `GET` | `/api/backup-items/:id` | Récupère un backup item |
| `POST` | `/api/backups/:backupId/items` | Ajoute un item à un backup existant |
| `PUT` | `/api/backup-items/:id` | Modifie un backup item |
| `DELETE` | `/api/backup-items/:id` | Supprime un backup item |

---

## Flow de création d'un Backup

### Étape 1: Créer un backup avec ses items (méthode recommandée)

```http
POST /api/clusters/6507a1b2c3d4e5f6a7b8c9d0/backups
Content-Type: application/json

{
  "database_type": "postgresql",
  "date": "2024-01-15T02:00:00Z",
  "size": "2.5GB",
  "backupItems": [
    {
      "database_type": "postgresql",
      "name": "users_db",
      "admin_username": "postgres",
      "username": "app_user",
      "filename": "users_db_20240115.sql"
    },
    {
      "database_type": "postgresql",
      "name": "orders_db",
      "admin_username": "postgres",
      "username": "app_user",
      "filename": "orders_db_20240115.sql"
    }
  ]
}
```

**Réponse:**
```json
{
  "id": "6507a1b2c3d4e5f6a7b8c9d1",
  "database_type": "postgresql",
  "date": "2024-01-15T02:00:00.000Z",
  "size": "2.5GB",
  "clusterId": "6507a1b2c3d4e5f6a7b8c9d0",
  "backupItemCount": 2
}
```

### Étape 2 (optionnel): Ajouter un item à un backup existant

```http
POST /api/backups/6507a1b2c3d4e5f6a7b8c9d1/items
Content-Type: application/json

{
  "database_type": "postgresql",
  "name": "logs_db",
  "admin_username": "postgres",
  "username": "logger",
  "filename": "logs_db_20240115.sql",
  "date": "2024-01-15T02:00:00Z"
}
```

---

## Logique métier

### Création de Backup (BackupService.createBackup)

```typescript
async createBackup(clusterId: string, backupData: BackupCreateInput) {
  // Crée le backup ET tous ses BackupItems en une seule transaction
  const backup = await prisma.backup.create({
    data: {
      database_type: backupData.database_type,
      date: backupData.date,
      size: backupData.size,
      clusterId,
      BackupItem: {
        create: backupData.backupItems.map((item) => ({
          ...item,
          date: backupData.date, // Hérite la date du backup parent
        })),
      },
    },
    include: { BackupItem: true },
  })
  return { ...backup, backupItemCount: backup.BackupItem.length }
}
```

### Suppression de Backup (BackupService.deleteBackup)

```typescript
async deleteBackup(id: string) {
  // 1. Supprime d'abord tous les BackupItems liés
  await prisma.backupItem.deleteMany({
    where: { backupId: id },
  })
  
  // 2. Puis supprime le Backup
  const backup = await prisma.backup.delete({
    where: { id },
  })
  return backup
}
```

> ⚠️ Note: La suppression en cascade n'est pas configurée dans Prisma, donc le service gère manuellement la suppression des BackupItems.

---

## Cas d'usage typique

### Scénario: Backup nocturne automatisé

1. Un job CRON récupère la liste des clusters:
   ```
   GET /api/clusters
   ```

2. Pour chaque cluster, il récupère les databases:
   ```
   GET /api/databases?clusterId=xxx
   ```

3. Il effectue les backups physiques des BDD

4. Il enregistre le backup dans l'API:
   ```
   POST /api/clusters/:clusterId/backups
   {
     "database_type": "postgresql",
     "date": "2024-01-15T02:00:00Z",
     "size": "5.2GB",
     "backupItems": [
       { "name": "db1", "filename": "db1.sql", ... },
       { "name": "db2", "filename": "db2.sql", ... }
     ]
   }
   ```

### Scénario: Consultation des backups

1. Lister les backups d'un cluster:
   ```
   GET /api/backups?clusterId=xxx
   ```

2. Voir le détail d'un backup (avec la liste des BDD sauvegardées):
   ```
   GET /api/backups/:id
   ```

---

## Champs importants

### BackupItem.name
Le nom de la base de données qui a été sauvegardée (ex: `users_db`, `orders_db`)

### BackupItem.username
Le propriétaire de la base de données (utile pour la restauration)

### BackupItem.admin_username
Le compte administrateur utilisé pour effectuer le backup (ex: `postgres`)

### BackupItem.filename
Le nom du fichier de backup sur le stockage (ex: `users_db_20240115_020000.sql.gz`)

### Backup.size
La taille totale du backup (somme de tous les fichiers BackupItem)
