# End - End UI Tests
### Overview
The End - End UI framework is based on [Cucumber](https://github.com/cucumber-rs/cucumber "Cucumber") and [Thrityfour](https://github.com/stevepryde/thirtyfour/tree/main/thirtyfour "Thrityfour"). The tests are written in Gherkin format and they are executed with the aid of cucumber-rs. 

The tests under package e2e-tests can be run with the below command,
```shell
git clone https://github.com/trustification/trustification
cd e2e-tests 
cargo run -- --application http://localhost:8084/ --user-name admin --password admin123456
```
### Usage
Clone the Trustification repository using the provided URL.
Navigate to the e2e-tests directory.
Execute the tests using cargo run with the following command-line arguments:
- `--application:` The URL of the application under test.
- `--user-name:` The username for logging into the application.
- `--password:`   The password for logging into the application.


**Note**
Ensure that you have [chromedriver](https://chromedriver.chromium.org/downloads) compatible to your chrome browser version is installed on your system and that the environment path has been properly configured.

### References
For more information, you can refer to the following resources:

1. [Cucumber](https://github.com/cucumber-rs/cucumber "Cucumber"): Cucumber for Rust, the framework used for writing and running tests in Gherkin format.
2.  [Thirtyfour](https://github.com/stevepryde/thirtyfour/tree/main/thirtyfour "Thirtyfour"): Thirtyfour is a Selenium WebDriver library for Rust, which is used for browser automation in your UI tests.
These references provide detailed information about the tools and libraries used in your End-to-End UI testing framework.