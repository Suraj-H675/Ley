pub mod analyzer;
mod controlled_crawler;
mod crawler;
mod demo;
pub mod html;
pub mod index;
mod page_policy;
mod query;
mod robots;
mod safe_fetch;
pub mod storage;
pub mod url_key;

#[cfg(test)]
mod reference;

pub use demo::{
    DemoError, DemoOutput, DemoStats, run_controlled_fixture_demo, run_demo, run_demo_with_options,
};
