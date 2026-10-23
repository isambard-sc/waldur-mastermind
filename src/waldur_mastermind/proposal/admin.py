from django.contrib import admin

from . import models


class RequestedOfferingInline(admin.TabularInline):
    model = models.RequestedOffering
    extra = 1


class RoundInline(admin.TabularInline):
    model = models.Round
    extra = 1


class CallResourceTemplateInline(admin.TabularInline):
    model = models.CallResourceTemplate
    extra = 0
    readonly_fields = ("created_by",)


class RequestedResourceInline(admin.TabularInline):
    model = models.RequestedResource
    extra = 1


class FormbricksFlowStepInline(admin.TabularInline):
    model = models.FormbricksFlowStep
    extra = 0
    fields = (
        "order",
        "key",
        "survey_id",
        "mapper",
        "is_reviewer_visible",
        "resource_question_id",
    )


class FormbricksFlowAdmin(admin.ModelAdmin):
    inlines = [FormbricksFlowStepInline]
    list_display = ("name", "created")
    search_fields = ("name",)


class FormbricksFieldMappingInline(admin.TabularInline):
    model = models.FormbricksFieldMapping
    extra = 0


class FormbricksResourceOptionInline(admin.TabularInline):
    model = models.FormbricksResourceOption
    extra = 0
    raw_id_fields = ("offering",)


class FormbricksFlowStepAdmin(admin.ModelAdmin):
    inlines = [FormbricksFieldMappingInline, FormbricksResourceOptionInline]
    list_display = ("flow", "order", "key", "survey_id", "mapper")
    list_filter = ("flow",)


class CallAdmin(admin.ModelAdmin):
    inlines = [RequestedOfferingInline, RoundInline, CallResourceTemplateInline]
    list_display = (
        "name",
        "state",
        "fixed_duration_in_days",
        "formbricks_flow",
        "reviewer_identity_visible_to_submitters",
        "reviews_visible_to_submitters",
    )
    fieldsets = (
        (
            None,
            {
                "fields": (
                    "name",
                    "description",
                    "manager",
                    "state",
                )
            },
        ),
        (
            "Configuration",
            {
                "fields": (
                    "fixed_duration_in_days",
                    "external_url",
                    "backend_id",
                )
            },
        ),
        (
            "Formbricks-driven intake",
            {
                "fields": ("formbricks_flow",),
                "description": "Pick a Formbricks flow to use instead of the "
                "legacy Waldur-native proposal form for this call. Leave blank "
                "for the legacy form.",
            },
        ),
        (
            "Visibility settings",
            {
                "fields": (
                    "reviewer_identity_visible_to_submitters",
                    "reviews_visible_to_submitters",
                ),
                "description": "Control what proposal submitters can see about reviews",
            },
        ),
    )


class ProposalProjectRoleMappingAdmin(admin.ModelAdmin):
    list_display = ("call", "proposal_role", "project_role")
    search_fields = ("call__name", "proposal_role__name", "project_role__name")


class RoundAdmin(admin.ModelAdmin):
    list_display = ("call", "start_time", "cutoff_time")


class ProposalAdmin(admin.ModelAdmin):
    inlines = [RequestedResourceInline]
    list_display = ("__str__", "get_state_display")


class ReviewAdmin(admin.ModelAdmin):
    list_display = ("reviewer", "proposal")


class FormStepResponseAdmin(admin.ModelAdmin):
    list_display = ("proposal", "step_key", "survey_id", "response_id", "created")
    list_filter = ("step_key",)
    readonly_fields = ("raw_response", "question_labels")


admin.site.register(models.CallManagingOrganisation)
admin.site.register(models.Call, CallAdmin)
admin.site.register(models.FormbricksFlow, FormbricksFlowAdmin)
admin.site.register(models.FormbricksFlowStep, FormbricksFlowStepAdmin)
admin.site.register(models.ProposalProjectRoleMapping, ProposalProjectRoleMappingAdmin)
admin.site.register(models.CallResourceTemplate)
admin.site.register(models.Round, RoundAdmin)
admin.site.register(models.Proposal, ProposalAdmin)
admin.site.register(models.Review, ReviewAdmin)
admin.site.register(models.FormStepResponse, FormStepResponseAdmin)
