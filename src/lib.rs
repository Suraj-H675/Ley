pub mod analyzer;
mod crawler;
mod demo;
pub mod html;
pub mod index;
mod query;
pub mod url_key;

#[cfg(test)]
mod reference;

pub use demo::{DemoError, DemoOutput, DemoStats, run_demo, run_demo_with_options};
