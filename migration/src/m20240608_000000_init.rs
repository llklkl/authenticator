use sea_orm_migration::prelude::*;
use sea_orm::{DeriveIden, Iden};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(
            Table::create()
                .table(Secrets::Table).if_not_exists()
                .col(ColumnDef::new(Secrets::Id).string().not_null().primary_key())
                .col(ColumnDef::new(Secrets::VGid).string().not_null())
                .col(ColumnDef::new(Secrets::Name).string().not_null())
                .col(ColumnDef::new(Secrets::Digits).integer().not_null())
                .col(ColumnDef::new(Secrets::Counter).integer().not_null())
                .col(ColumnDef::new(Secrets::Algorithm).string().not_null())
                .col(ColumnDef::new(Secrets::Period).integer().not_null())
                .col(ColumnDef::new(Secrets::Issuer).string().not_null())
                .col(ColumnDef::new(Secrets::Deleted).integer().not_null())
                .col(ColumnDef::new(Secrets::CreatedAt).big_integer().not_null())
                .col(ColumnDef::new(Secrets::UpdatedAt).big_integer().not_null())
                .to_owned(),
        ).await?;

        manager.create_index(
            Index::create()
                .table(Secrets::Table).if_not_exists()
                .name(Secrets::IdxVGidDeletedCreatedAt.to_string())
                .col(Secrets::VGid)
                .col(Secrets::Deleted)
                .col(Secrets::CreatedAt)
                .to_owned()
        ).await?;

        manager.create_table(
            Table::create()
                .table(SecretsHistory::Table).if_not_exists()
                .col(ColumnDef::new(SecretsHistory::Id).string().not_null().primary_key())
                .col(ColumnDef::new(SecretsHistory::SecretId).string().not_null())
                .col(ColumnDef::new(SecretsHistory::Name).string().not_null())
                .col(ColumnDef::new(SecretsHistory::Digits).integer().not_null())
                .col(ColumnDef::new(SecretsHistory::Counter).integer().not_null())
                .col(ColumnDef::new(SecretsHistory::Algorithm).string().not_null())
                .col(ColumnDef::new(SecretsHistory::Period).integer().not_null())
                .col(ColumnDef::new(SecretsHistory::Issuer).string().not_null())
                .col(ColumnDef::new(SecretsHistory::Deleted).integer().not_null())
                .col(ColumnDef::new(SecretsHistory::CreatedAt).big_integer().not_null())
                .col(ColumnDef::new(SecretsHistory::UpdatedAt).big_integer().not_null())
                .to_owned(),
        ).await?;
        manager.create_index(
            Index::create()
                .table(SecretsHistory::Table).if_not_exists()
                .name(SecretsHistory::IdxSecretIdCreatedAt.to_string())
                .col(SecretsHistory::SecretId)
                .col(SecretsHistory::CreatedAt)
                .to_owned()
        ).await?;

        manager.create_table(
            Table::create()
                .table(SecretsOriginData::Table).if_not_exists()
                .col(ColumnDef::new(SecretsOriginData::SecretId).string().not_null().primary_key())
                .col(ColumnDef::new(SecretsOriginData::Name).string().not_null())
                .col(ColumnDef::new(SecretsOriginData::OriginData).string().not_null())
                .col(ColumnDef::new(SecretsOriginData::CreatedAt).big_integer().not_null())
                .to_owned(),
        ).await?;

        manager.create_table(
            Table::create()
                .table(VGroup::Table).if_not_exists()
                .col(ColumnDef::new(VGroup::Id).string().not_null().primary_key())
                .col(ColumnDef::new(VGroup::Name).string().not_null())
                .col(ColumnDef::new(VGroup::Parent).string().not_null())
                .col(ColumnDef::new(VGroup::GType).integer().not_null())
                .col(ColumnDef::new(VGroup::Deleted).integer().not_null())
                .col(ColumnDef::new(VGroup::CreatedAt).big_integer().not_null())
                .col(ColumnDef::new(VGroup::UpdatedAt).big_integer().not_null())
                .to_owned(),
        ).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(
            Table::drop().table(Secrets::Table).to_owned()
        ).await?;

        manager.drop_table(
            Table::drop().table(SecretsHistory::Table).to_owned()
        ).await?;

        manager.drop_table(
            Table::drop().table(SecretsOriginData::Table).to_owned()
        ).await?;

        manager.drop_table(
            Table::drop().table(VGroup::Table).to_owned()
        ).await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Secrets {
    Table,
    Id,
    #[sea_orm(iden = "vgid")]
    VGid,
    Name,
    Digits,
    Counter,
    Algorithm,
    Period,
    Issuer,
    Deleted,
    CreatedAt,
    UpdatedAt,
    #[sea_orm(iden = "idx_vgid_deleted_created_at")]
    IdxVGidDeletedCreatedAt,
}

#[derive(DeriveIden)]
enum SecretsHistory {
    Table,
    Id,
    SecretId,
    Name,
    Digits,
    Counter,
    Algorithm,
    Period,
    Issuer,
    Deleted,
    CreatedAt,
    UpdatedAt,
    #[sea_orm(iden = "idx_secret_id_created_at")]
    IdxSecretIdCreatedAt,
}

#[derive(DeriveIden)]
enum SecretsOriginData {
    Table,
    SecretId,
    Name,
    OriginData,
    CreatedAt,
}

#[derive(DeriveIden)]
enum VGroup {
    #[sea_orm(iden = "vgroup")]
    Table,
    Id,
    Name,
    Parent,
    #[sea_orm(iden = "gtype")]
    GType,
    Deleted,
    CreatedAt,
    UpdatedAt,
}

