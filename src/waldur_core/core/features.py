from dataclasses import dataclass


@dataclass
class Feature:
    description: str


FEATURES = []


class FeatureSectionMetaclass(type):
    def __new__(self, name, bases, attrs):
        if "Meta" in attrs:
            section = {
                "key": attrs["Meta"].key,
                "description": attrs["Meta"].description,
                "items": [],
            }
            FEATURES.append(section)
            for key, feature in attrs.items():
                if isinstance(feature, Feature):
                    section["items"].append(
                        {"key": key, "description": feature.description}
                    )
        return type.__new__(self, name, bases, attrs)


class FeatureSection(metaclass=FeatureSectionMetaclass):
    pass


class CustomerSection(FeatureSection):
    class Meta:
        key = "customer"
        description = "Organization workspace"

    show_domain = Feature("Allows to hide domain field in organization detail.")

    payments_for_staff_only = Feature(
        "Make payments menu visible for staff users only."
    )
    show_permission_reviews = Feature(
        "Allows to show permission reviews tab and popups for organisations."
    )

    show_banking_data = Feature("Display banking related data under customer profile.")


class ProjectSection(FeatureSection):
    class Meta:
        key = "project"
        description = "Project workspace"

    estimated_cost = Feature("Render estimated cost column in projects list.")

    oecd_fos_2007_code = Feature("Enable OECD code.")

    show_industry_flag = Feature("Show industry flag.")

    show_description_in_create_dialog = Feature(
        "Show description field in project create dialog."
    )

    show_type_in_create_dialog = Feature("Show type field in project create dialog.")

    show_start_date_in_create_dialog = Feature(
        "Show start date field in project create dialog."
    )

    show_end_date_in_create_dialog = Feature(
        "Show end date field in project create dialog."
    )

    show_image_in_create_dialog = Feature("Show image field in project create dialog.")

    show_credit_in_create_dialog = Feature(
        "Show credit field in project create dialog."
    )

    mandatory_start_date = Feature("Make the project start date mandatory.")

    mandatory_end_date = Feature("Make the project end date mandatory.")

    show_permission_reviews = Feature(
        "Allows to show permission reviews tab and popups for projects."
    )

    show_kind_in_create_dialog = Feature("Show kind field in project create dialog.")

    enforce_allowed_domains = Feature(
        "Enforce allowed-domain restrictions from OpenPortal AwardDetails when "
        "adding or inviting users to a project."
    )

    show_openportal_accounting_pages = Feature(
        "Show OpenPortal accounting pages to users in the project workspace."
    )


class UserSection(FeatureSection):
    class Meta:
        key = "user"
        description = "User workspace"

    credentials = Feature(
        "Enable credentials management (SSH keys, API tokens, etc.) in user workspace."
    )

    disable_long_tokens = Feature(
        "Disallow non-staff/support users from creating API tokens with unlimited or long expiration times (more than an hour)."
    )

    preferred_language = Feature("Render preferred language column in users list.")

    ssh_keys = Feature("Enable SSH keys management in user workspace.")

    notifications = Feature(
        "Enable email and webhook notifications management in user workspace."
    )

    permission_requests = Feature(
        "Enable permission requests management in user workspace."
    )

    disable_user_termination = Feature("Disable user termination in user workspace.")

    show_slug = Feature("Enable display of slug field in user summary.")

    show_username = Feature("Enable display of username field in user tables.")

    show_slug_as_id = Feature(
        "Show the user slug as an identifier on the dashboard and all user lists."
    )

    minimal_user_profile = Feature(
        "Show and allow editing of minimal set of user profile fields (e.g. just name and email)."
    )

    allow_user_creation = Feature(
        "Allow users to create new user accounts when adding team members to projects and proposals."
    )


class MarketplaceSection(FeatureSection):
    class Meta:
        key = "marketplace"
        description = "Marketplace offerings and resources"

    import_resources = Feature(
        "Allow to import resources from service provider to project."
    )

    conceal_prices = Feature("Do not render prices in order details.")

    show_experimental_ui_components = Feature(
        "Enabled display of experimental or mocked components in marketplace."
    )

    show_call_management_functionality = Feature(
        "Enabled display of call management functionality."
    )

    lexis_links = Feature("Enabled LEXIS link integrations for offerings.")

    catalogue_only = Feature("Allow marketplace to function as a catalogue only.")

    call_only = Feature("Allow marketplace to serve only as aggregator of call info.")

    show_resource_end_date = Feature(
        "Show resource end date as a non optional column in resources list."
    )

    allow_display_of_images_in_markdown = Feature(
        "Allow display of images in markdown format."
    )
    display_user_tos = Feature("Enable display of user terms of service in UI.")

    show_managed_projects = Feature(
        "Allows to show managed (openportal) remote projects in organization."
    )

    display_software_catalog = Feature("Enable display of software catalog in UI.")

    display_offering_partitions = Feature(
        "Enable display of offering partitions in UI."
    )


class SupportSection(FeatureSection):
    class Meta:
        key = "support"
        description = "Support workspace"

    pricelist = Feature(
        "Render marketplace plan components pricelist in support workspace."
    )

    vm_type_overview = Feature("Enable VM type overview in support workspace.")

    conceal_change_request = Feature(
        'Conceal "Change request" from a selection of issue types for non-staff/non-support users.'
    )


class InvitationsSection(FeatureSection):
    class Meta:
        key = "invitations"
        description = "Invitations management"

    conceal_civil_number = Feature(
        "Conceal civil number in invitation creation dialog."
    )
    civil_number_required = Feature(
        "Make civil number field mandatory in invitation creation form."
    )
    show_service_accounts = Feature("Show service accounts of the scopes.")
    show_course_accounts = Feature("Show course accounts of the scopes.")


class RancherSection(FeatureSection):
    class Meta:
        key = "rancher"
        description = "Rancher resources provisioning"

    volume_mount_point = Feature(
        "Allow to select mount point for data volume when Rancher cluster is provisioned."
    )

    apps = Feature("Render Rancher apps as a separate tab in resource details page.")


class SlurmSection(FeatureSection):
    class Meta:
        key = "slurm"
        description = "SLURM resources provisioning"

    jobs = Feature(
        "Render list of SLURM jobs as a separate tab in allocation details page."
    )


class OpenstackSection(FeatureSection):
    class Meta:
        key = "openstack"
        description = "OpenStack resources provisioning"

    hide_volume_type_selector = Feature(
        "Allow to hide OpenStack volume type selector when instance or volume is provisioned."
    )
    show_migrations = Feature("Show OpenStack tenant migrations action and tab")


class WaldurDeploymentSection(FeatureSection):
    class Meta:
        key = "deployment"
        description = "Waldur deployment settings"

    send_metrics = Feature("Send telemetry metrics.")
    enable_cookie_notice = Feature("Enable cookie notice in marketplace.")
    application_portal_only = Feature(
        "Configure Waldur to function as an application and awards portal only."
    )
    make_slugs_immutable = Feature(
        "Make slugs immutable, i.e. disallow direct changes to slugs after they have been set. Note that slugs may still be changed indirectly."
    )
