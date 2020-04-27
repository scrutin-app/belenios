#!/usr/bin/python
# coding: utf-8
import time
from selenium.webdriver.common.alert import Alert
from util.selenium_tools import wait_for_an_element_exists_and_is_visible_and_contains_expected_text, wait_for_an_element_exists_and_is_visible_and_attribute_contains_expected_text, wait_for_element_exists, wait_for_elements_exist, wait_for_an_element_with_link_text_exists, wait_for_element_exists_and_contains_expected_text, wait_for_element_exists_and_has_non_empty_content
from util.election_testing import wait_a_bit, election_home_find_start_button


class SeleniumPageObjectModel():
    """
    Classes which inherit from SeleniumPageObjectModel are meant to follow the "Page Object" design pattern of Selenium, as described here: https://www.selenium.dev/documentation/en/guidelines_and_recommendations/page_object_models/
    """
    def __init__(self, browser, timeout):
        self.browser = browser
        self.timeout = timeout


    def click_on_link_with_expected_label(self, expected_label):
        link_element = wait_for_an_element_with_link_text_exists(self.browser, expected_label, self.timeout)
        link_element.click()


class VerifiablePage(SeleniumPageObjectModel):
    def verify_page(self):
        raise NotImplementedError()


class ClickableLogoPage(SeleniumPageObjectModel):
    def click_on_logo_image(self):
        logo_image_element = wait_for_element_exists(self.browser, "#header a", self.timeout) # maybe we should edit the DOM of the page to allow for a more specific CSS selector?
        logo_image_element.click()


class ElectionHomePage(VerifiablePage):
    def verify_page(self):
        election_home_find_start_button(self.browser)


    def click_on_language_link(self, language_link_label):
        self.click_on_link_with_expected_label(language_link_label)


    def click_on_start_button(self):
        start_button_label = "Start"
        start_button_css_selector = "#main button"
        start_button_element = wait_for_element_exists_and_contains_expected_text(self.browser, start_button_css_selector, start_button_label, self.timeout)
        start_button_element.click()


    def click_on_advanced_mode_link(self):
        self.click_on_language_link("en") # in order to see the following label in the correct language
        self.click_on_link_with_expected_label("Advanced mode")


    def click_on_see_accepted_ballots_link(self):
        self.click_on_language_link("en") # in order to see the following label in the correct language
        self.click_on_link_with_expected_label("See accepted ballots")


    def click_on_accept_personal_data_policy_link(self):
        self.click_on_link_with_expected_label("Accept")


class NormalVoteGenericStepPage(VerifiablePage):
    current_step_css_selector = ".current_step"
    expected_step_content = "Step"


    def verify_step_title(self):
        wait_for_an_element_exists_and_is_visible_and_contains_expected_text(self.browser, self.current_step_css_selector, self.expected_step_content, self.timeout)


    def verify_page(self):
        self.verify_step_title()


class NormalVoteStep1Page(NormalVoteGenericStepPage):
    expected_step_content = "Step 1/6: Input credential"


    def click_on_here_button_and_type_voter_credential(self, voter_credential):
        here_button_label = "here"
        here_button_css_selector = "#main button"
        here_button_element = wait_for_element_exists_and_contains_expected_text(self.browser, here_button_css_selector, here_button_label, self.timeout)
        here_button_element.click()

        wait_a_bit()

        # A modal opens (it is an HTML modal created using Window.prompt()), with an input field. He types his credential.
        credential_prompt = Alert(self.browser)
        credential_prompt.send_keys(voter_credential)
        credential_prompt.accept()


    def click_on_here_button_and_type_wrong_voter_credential(self, voter_credential):
        self.click_on_here_button_and_type_voter_credential(voter_credential)

        # Another modal opens (it is an HTML modal created using Window.alert()).
        time.sleep(2)
        failure_alert = Alert(self.browser)
        failure_alert.accept()


class NormalVoteStep2Page(NormalVoteGenericStepPage):
    expected_step_content = "Step 2/6: Answer to questions"


    def click_on_next_button(self):
        step_2_parent_css_selector = "#question_div"
        next_button = wait_for_an_element_exists_and_is_visible_and_contains_expected_text(self.browser, step_2_parent_css_selector + " button", "Next", self.timeout)
        next_button.click()


    def click_on_next_button_but_form_is_not_filled(self):
        self.click_on_next_button()

        # Another modal opens (it is an HTML modal created using Window.alert()).
        failure_alert = Alert(self.browser)
        failure_alert.accept()


class NormalVoteGenericStepWithBallotTrackerPage(NormalVoteGenericStepPage):
    def get_smart_ballot_tracker_value(self):
        smart_ballot_tracker_css_selector = "#ballot_tracker"
        smart_ballot_tracker_element = wait_for_element_exists_and_has_non_empty_content(self.browser, smart_ballot_tracker_css_selector, self.timeout)
        smart_ballot_tracker_value = smart_ballot_tracker_element.get_attribute('innerText')
        return smart_ballot_tracker_value


    def verify_ballot_tracker_value(self):
        smart_ballot_tracker_value = self.get_smart_ballot_tracker_value()
        assert len(smart_ballot_tracker_value) > 5


class NormalVoteStep3Page(NormalVoteGenericStepWithBallotTrackerPage):
    expected_step_content = "Step 3/6: Review and encrypt"


    def verify_page_body(self):
        step_3_parent_css_selector = "#ballot_div"
        step_3_expected_success_content = "Your ballot has been successfully encrypted"
        wait_for_an_element_exists_and_is_visible_and_contains_expected_text(self.browser, step_3_parent_css_selector, step_3_expected_success_content, self.timeout)
        self.verify_ballot_tracker_value()


    def verify_page(self):
        NormalVoteGenericStepWithBallotTrackerPage.verify_page(self)
        self.verify_page_body()


    def click_on_continue_button(self):
        continue_button_element = wait_for_an_element_exists_and_is_visible_and_attribute_contains_expected_text(self.browser, "input[type=submit]", "value", "Continue", self.timeout)
        continue_button_element.click()


    def click_on_restart_button(self):
        restart_button_element = wait_for_an_element_exists_and_is_visible_and_contains_expected_text(self.browser, "button", "Restart", self.timeout)
        restart_button_element.click()


class VoterLoginPage(VerifiablePage, ClickableLogoPage):
    login_form_username_css_selector = '#main form input[name=username]'
    login_form_password_css_selector = '#main form input[name=password]'
    login_form_submit_css_selector = '#main form input[type=submit]'


    def verify_page(self):
        wait_for_an_element_exists_and_is_visible_and_contains_expected_text(self.browser, "h1", "Password login", self.timeout)


    def fill_form(self, username, password):
        login_form_username_value = username # correct value: settings.ADMINISTRATOR_USERNAME
        login_form_password_value = password # correct value: settings.ADMINISTRATOR_PASSWORD

        login_form_username_element = wait_for_element_exists(self.browser, self.login_form_username_css_selector, self.timeout)
        login_form_password_element = wait_for_element_exists(self.browser, self.login_form_password_css_selector, self.timeout)

        login_form_username_element.clear()
        login_form_username_element.send_keys(login_form_username_value)
        login_form_password_element.clear()
        login_form_password_element.send_keys(login_form_password_value)


    def click_on_login_button(self):
        login_button_element = wait_for_an_element_exists_and_is_visible_and_attribute_contains_expected_text(self.browser, self.login_form_submit_css_selector, "value", "Login", self.timeout)
        login_button_element.submit()


    def log_in(self, username, password):
        self.fill_form(username, password)
        wait_a_bit()
        self.click_on_login_button()


class UnauthorizedPage(VerifiablePage):
    def verify_page(self):
        wait_for_an_element_exists_and_is_visible_and_contains_expected_text(self.browser, "h1", "Unauthorized", self.timeout)


class ServerHomePage(VerifiablePage):
    def verify_page(self):
        assert self.browser.current_url.endswith("/admin") is True


class NormalVoteStep5Page(NormalVoteGenericStepWithBallotTrackerPage, ClickableLogoPage):
    expected_step_content = "Step 5/6: Confirm"


    def verify_page_body(self, expected_ballot_tracker, expected_username):
        step_5_parent_css_selector = "#main"
        step_5_expected_success_content = "has been received, but not recorded yet"
        wait_for_an_element_exists_and_is_visible_and_contains_expected_text(self.browser, step_5_parent_css_selector, step_5_expected_success_content, self.timeout)
        self.verify_ballot_tracker_value()
        ballot_tracker_value = self.get_smart_ballot_tracker_value()
        assert ballot_tracker_value == expected_ballot_tracker

        wait_for_an_element_exists_and_is_visible_and_contains_expected_text(self.browser, step_5_parent_css_selector, expected_username, self.timeout)


    def verify_page(self, expected_ballot_tracker, expected_username):
        NormalVoteGenericStepWithBallotTrackerPage.verify_page(self)
        self.verify_page_body(expected_ballot_tracker, expected_username)


    def click_on_i_cast_my_vote_button(self):
        i_cast_my_vote_button_label = "I cast my vote"
        i_cast_my_vote_button_element = wait_for_an_element_exists_and_is_visible_and_attribute_contains_expected_text(self.browser, "input[type=submit]", "value", i_cast_my_vote_button_label, self.timeout)
        i_cast_my_vote_button_element.click()


    def click_on_go_back_to_election_link(self):
        self.click_on_link_with_expected_label("Go back to election")


class NormalVoteStep6Page(NormalVoteGenericStepWithBallotTrackerPage):
    expected_step_content = "Step 6/6: Thank you for voting!"


    def verify_page_body(self, expected_ballot_tracker):
        step_6_parent_css_selector = "#main"
        expected_step_6_body_content = "has been accepted"
        wait_for_an_element_exists_and_is_visible_and_contains_expected_text(self.browser, step_6_parent_css_selector, expected_step_6_body_content, self.timeout)
        self.verify_ballot_tracker_value()
        ballot_tracker_value = self.get_smart_ballot_tracker_value()
        assert ballot_tracker_value == expected_ballot_tracker


    def verify_page(self, expected_ballot_tracker):
        NormalVoteGenericStepWithBallotTrackerPage.verify_page(self)
        self.verify_page_body(expected_ballot_tracker)


    def click_on_ballot_box_link(self):
        self.click_on_link_with_expected_label("ballot box")


    def click_on_go_back_to_election_link(self):
        self.click_on_link_with_expected_label("Go back to election")


class BallotBoxPage(VerifiablePage):
    def verify_header(self):
        wait_for_an_element_exists_and_is_visible_and_contains_expected_text(self.browser, "#header h1", "Accepted ballots", self.timeout)


    def verify_presence_of_expected_ballot_tracker(self, expected_ballot_tracker):
        all_smart_ballot_trackers_css_selector = "#main ul li a"
        all_smart_ballot_trackers_elements = wait_for_elements_exist(self.browser, all_smart_ballot_trackers_css_selector, self.timeout)
        assert len(all_smart_ballot_trackers_elements)
        matches = [element for element in all_smart_ballot_trackers_elements if element.get_attribute('innerText') == expected_ballot_tracker]
        assert len(matches) == 1


    def verify_page(self, expected_ballot_tracker=None):
        self.verify_header()
        if expected_ballot_tracker:
            self.verify_presence_of_expected_ballot_tracker(expected_ballot_tracker)


    def click_on_ballot_link(self, ballot_tracker):
        self.click_on_link_with_expected_label(ballot_tracker)


    def click_on_go_back_to_election_link(self):
        self.click_on_link_with_expected_label("Go back to election")


class AdvancedModeVotePage(VerifiablePage):
    def verify_page(self):
        wait_for_element_exists(self.browser, "input[type=file][name=encrypted_vote]")


    def click_on_back_to_election_home_link(self):
        self.click_on_link_with_expected_label("Back to election home")

    # TODO: other links in the page, fill both forms, submit them
