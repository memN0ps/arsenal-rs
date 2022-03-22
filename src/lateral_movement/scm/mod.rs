
use std::{thread, time};

#[derive(Debug, Clone)]
pub struct PSExec {
    pub computer_name: String,
    pub binary_path: String,
    pub service_name: String,
    pub display_name: String
}

impl PSExec {
    pub fn new(input_computer_name: String, input_binary_path: String, input_service_name: Option<String>, input_display_name: Option<String>) -> Self {
        if let Some(input_service_name) = input_service_name {
            if let Some(input_display_name) = input_display_name {
                return Self {
                    computer_name: input_computer_name,
                    binary_path: input_binary_path,
                    service_name: input_service_name,
                    display_name: input_display_name,
                }
            }
            return Self {
                computer_name: input_computer_name,
                binary_path: input_binary_path,
                service_name: input_service_name,
                display_name: "mimiRust Service".to_string(),
            }
        }
        Self {
            computer_name: input_computer_name,
            binary_path: input_binary_path,
            service_name: "mimiRust".to_string(),
            display_name: "mimiRust Service".to_string(),
        }
    }

    pub fn execute(config: Self) -> bool {
        todo!();
    }
}