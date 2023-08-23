// use crate::certificates::end_entity::end_entity_cert_cli;
// use crate::certificates::intermediate::{build_intermediate_ca, intermediate_ca_from_folder};
// use crate::certificates::root::{build_root_ca, root_ca_from_folder};
// use crate::cli::{BootstrapOptions, BootstrapStage};
// use tokio::fs;
//
// pub const OUT_DIR_BASE: &str = "ca";
// pub const OUT_DIR_ROOT: &str = "ca/root";
// pub const OUT_DIR_INTERMEDIATE: &str = "ca/intermediate";
// pub const OUT_DIR_END_ENTITY: &str = "ca/end_entity";
// pub const SERIAL_PATH: &str = "ca/end_entity/serial";
//
// pub async fn bootstrap(opt: BootstrapOptions) -> Result<(), anyhow::Error> {
//     if opt.stage == BootstrapStage::Root || opt.stage == BootstrapStage::Full {
//         if opt.clean {
//             // removing a non-existing dir anyway will fail -> ignore it
//             let _ = fs::remove_dir_all(OUT_DIR_BASE).await;
//             fs::create_dir(OUT_DIR_BASE).await?;
//         }
//
//         build_root_ca(&opt).await?;
//     }
//
//     if opt.stage == BootstrapStage::Intermediate || opt.stage == BootstrapStage::Full {
//         // do read the ca private in from file again to make sure everything works out fine
//         let root_cert = root_ca_from_folder().await?;
//
//         // build intermediate
//         build_intermediate_ca(&opt, &root_cert).await?;
//     }
//
//     // This should only be needed for the very first bootstrap or disaster recovery
//     if opt.stage == BootstrapStage::EndEntity || opt.stage == BootstrapStage::Full {
//         // do read the ca private in from file again to make sure everything works out fine
//         let intermediate_cert = intermediate_ca_from_folder().await?;
//
//         // build intermediate
//         end_entity_cert_cli(&opt, &intermediate_cert).await?;
//     }
//
//     Ok(())
// }
//
// pub async fn check_out_dir(
//     path: &str,
//     opt: &BootstrapOptions,
//     over_write: bool,
// ) -> Result<(), anyhow::Error> {
//     if fs::read_dir(OUT_DIR_BASE).await.is_err() {
//         fs::create_dir(OUT_DIR_BASE).await?;
//     }
//
//     match fs::read_dir(path).await {
//         Ok(_) => {
//             if over_write {
//                 Ok(())
//             } else if opt.clean {
//                 let _ = fs::remove_dir_all(path).await;
//                 fs::create_dir(path).await?;
//                 Ok(())
//             } else {
//                 let msg = format!(
//                     "Output dir '{}' already exists - exiting to not override existing data",
//                     path
//                 );
//                 Err(anyhow::Error::msg(msg))
//             }
//         }
//         Err(_) => {
//             // if the directory does not exist, create it and go on
//             fs::create_dir(path).await?;
//             Ok(())
//         }
//     }
// }
