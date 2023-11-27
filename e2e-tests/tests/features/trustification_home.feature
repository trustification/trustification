Feature: Trustification Home Page
    Scenario: The user should be able to search SBOM from home screen
        Given The user is on the Trustification home screen
        When The user Enters Search for "quarkus-bom" in the search field
        Then The list of SBOMs should displayed related to "quarkus-bom"

    Scenario: The Application Should Preserve Page State When The User Click Back Button
        Given The user is on the Trustification home screen
        When The user Enters Search for "quarkus-bom" in the search field
        And The user Navigates to Home screen and Clicks on Back Button
        Then The application should preserve page state and retrieve SBOM search results for "quarkus-bom"