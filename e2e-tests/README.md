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
This framework is capable of maintaining the driver executables for browsers. The script is available [here](/src/scripts/env.sh) for reference.

### Selenium
[Selenium](https://www.selenium.dev/documentation/overview/ "Selenium") is a popular open-source framework for automating web browsers. It provides a way to automate browser activities, such as navigating to websites, interacting with web elements, and performing various tasks on web applications.

The core of Selenium is [Webdriver](https://www.selenium.dev/documentation/webdriver/ "Webdriver"), which is an API interface. Each browser has its own driver (eg.chromedriver) which as an executable with implementations for the instructions from Selenium Webdriver. So, the driver is responsible for communication between Selenium and Browser. WebDriver follows W3C standards which maintains the interoperatability across different browsers.

In this framework, we use the crate [thirtyfour](https://github.com/stevepryde/thirtyfour "thirtyfour") which is the Selenium/ Webdriver library for Rust along with Cucumber.

#### How it works?
Selenium Webdriver uses client-server architecture. 
 - Client: The local machine which has the script 
 - Server: Driver executable and Browser
 
WebDriver uses W3C webdriver standard protocol to send requests and receive responses between the client (script) and the server (driver executable and browser)

For [thirtyfour](https://github.com/stevepryde/thirtyfour "thirtyfour"), we should have driver executables to be installed and running. When we create an instance for the [driver](https://github.com/stevepryde/thirtyfour/blob/86bd74c02bb850213f3199378d17bc9b2bf5afe8/thirtyfour/src/webdriver.rs#L110 "driver"), it creates a `SessionId` with the driver executable. This`SessionId` is attached to all of the browser actions followed on the script. 

   |  Script | <===> | Webdriver | <===> | Driver Executable | <====> | Browser |

In simple terms, Each browser action (like click, scroll,..) has its own API [endpoint](https://github.com/jonhoo/fantoccini/blob/c6e3a4513c9375c223f5c85e95ca69ad724c2ada/src/session.rs#L40 "endpoints").  The script invokes the API endpoints to perform the user actions on the browser, through webdriver and driver executable. Based on the response, the script will proceed to the next step or fails for the exception. The [exceptions](https://github.com/jonhoo/fantoccini/blob/main/src/error.rs "exceptions") could be Session related or Element related or other issues.

#### Cucumber
[Cucumber](https://cucumber.io/docs/guides/overview/ "Cucumber") is a Behavior-Driven Development (BDD) framework that allows teams to write executable specifications in plain language, making it easier to understand and automate application behavior for testing and collaboration.

In order for Cucumber to understand the scenarios, they must follow Gherkin syntax rules. Gherkin uses special keywords to give structure and meaning to excutable specifications. 

For example, in the below block is a scenario written for "Trustification Home Page" feature. It verifies, whether the user is able to view the list of SBOM for the given search criteria on the application. The keywords are Feature, Scenario, Given, When and Then. Here Feature and Scenario are for documetation purpose like test suite and test name, where as the user should implement definition for Given, When and Then in scripting.

    Feature: Trustification Home Page
        Scenario: The user should be able to search SBOM from home screen
            Given The user is on the Trustification home screen
            When The user Enters Search for "amq-7" in the search field
            Then The list of SBOMs should displayed related to "amq-7"

#### Selenium-manager
This framework includes [Selenium-manager](https://www.selenium.dev/documentation/selenium_manager/ "Selenium-manager") under /src/scripts/env.sh file to maintain the driver executable for the Chrome browser. The Current version executes the tests with Chrome browser by default.

#### Contribution
- Fork the repository
- Create a new branch
- Commit your changes
- Commits must be signed-off 
- Create a pull request against the main branch
  ##### Code Walkthrough
 - [Cargo.toml](./Cargo.toml) is manifest file to specify the dependencies for the framework
 - [features](./tests/features) directory contains the files with `.feature` extension which contains the scenarios written in Gherkin standard in plain text.
  - [pages](/src/pages) directory contains the implementation for the test steps defined to the scenarios under feature files. 
  - [main.rs](/src/main.rs) file has the `main` function defined, it is responsible receiving and intrepreting the CLI arguments,  Webdriver Setup and Teardown and Cucumber context for execution
  - [env.sh](/src/scripts/env.sh) script used to setup and teardown driver executables for the test run using [selenium-manager](https://github.com/SeleniumHQ/selenium/tree/trunk/rust "selenium-manager")
  ##### Example
  As mentioned earlier, below scenario verifies whether the SBOMs related to given search criteroa is displayed on SPOG UI. 

```
    Feature: Trustification Home Page
        Scenario: The user should be able to search SBOM from home screen
            Given The user is on the Trustification home screen
            When The user Enters Search for "amq-7" in the search field
            Then The list of SBOMs should displayed related to "amq-7"
```

The first two lines defined the feature and scenario which is equivalant to test suite and test case name. We have to implement the test steps which are identified with the keywords `Given`, `When` and `Then` as prefix.

These steps are implemented on a rust file under /src/pages directory as,

```
		#[given(expr = "The user is on the Trustification home screen")]
		async fn login_to_application(world: &mut E2EWorld) {
			let driver: &WebDriver = world.context.get_driver().unwrap();
			let application = world.application.as_ref().expect("Error").as_str();
			driver.goto(application).await.expect("Failed to load application");
			consent_deny(driver).await;
			// test steps
			}
```

The definition of the funtions should have cucumber attributes enclosed with #[] to indicate this is test step for the scenario. On the above example, the test step `Given The user is on the Trustification home screen` defined with the cucumber attribute `#[given(expr = The user is on the Trustification home screen )]`. Please note, the keyword `given` is not used in the expression.

So with this we can write our tests and its validation steps under features directory and the definitions for the test steps implemented under rust files with the aid of thirtyfour crate. 

### References
For more information, you can refer to the following resources:

1. [Cucumber](https://github.com/cucumber-rs/cucumber "Cucumber"): Cucumber for Rust, the framework used for writing and running tests in Gherkin format.
2.  [Thirtyfour](https://github.com/stevepryde/thirtyfour/tree/main/thirtyfour "Thirtyfour"): Thirtyfour is a Selenium WebDriver library for Rust, which is used for browser automation in your UI tests.
These references provide detailed information about the tools and libraries used in your End-to-End UI testing framework.