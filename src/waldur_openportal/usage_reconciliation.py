"""Bringing a completed month's billing into line with its usage report.

A month's usage keeps arriving after the month ends (the cluster reports the
last hours late, a site adds a spend-profile forfeit on the period's last
day), but usage is billed as it is reported for the current month only. Once
a past month's report is complete, the ComponentUsage billed for it is
corrected to the report's total, and the project's credit by the change.

Shared by the awarding side (RemoteOpenPortalBackend, RemoteAllocation and
HistoricalRemoteAllocation) and the site side (OpenPortalBackend,
Allocation and HistoricalAllocation): both bill a "node" component.
"""

import datetime
import decimal
import logging

from django.core.exceptions import ObjectDoesNotExist

from waldur_core.core import utils as core_utils
from waldur_mastermind.invoices import models as invoice_models
from waldur_mastermind.marketplace import models as marketplace_models
from waldur_mastermind.marketplace import utils as marketplace_utils

logger = logging.getLogger(__name__)


class UsageReconciliationMixin:
    def _adjust_project_credits_for_reconciliation(
        self, resource, month_date: datetime.date, usage_change: float
    ):
        """
        Adjust project credits to account for billing reconciliation changes.

        When we correct historical usage, the invoice items change but credits have
        already been deducted. This method adjusts the project credit balance to
        compensate for the billing change.

        Args:
            resource: The marketplace Resource
            month_date: The month being reconciled
            usage_change: The change in usage (positive = more usage, negative = less usage)
        """
        # Skip if no change
        if abs(usage_change) < 0.015:
            return

        project = resource.project
        customer = project.customer

        # Get the invoice for this month
        try:
            invoice = invoice_models.Invoice.objects.get(
                customer=customer, year=month_date.year, month=month_date.month
            )
        except invoice_models.Invoice.DoesNotExist:
            logger.warning(
                f"No invoice found for {customer} {month_date.year}-{month_date.month:02d} - "
                f"cannot adjust credits"
            )
            return

        # Update the invoice cache to reflect new totals
        invoice.update_cache()

        # Get project credit if it exists
        project_credit = invoice_models.ProjectCredit.objects.filter(
            project=project
        ).first()

        if not project_credit:
            logger.debug(
                f"No project credit for {project.name} - no credit adjustment needed"
            )
            return

        # Calculate the billing change
        # usage_change is in hours, we need to convert to cost
        # Get the plan component to find the unit price
        try:
            plan = resource.plan
            offering_component = marketplace_models.OfferingComponent.objects.get(
                offering=resource.offering, type="node"
            )
            plan_component = plan.components.get(component=offering_component)
            unit_price = float(plan_component.price)
        except Exception as e:
            logger.error(
                f"Could not determine unit price for {resource}: {e} - "
                f"cannot adjust credits"
            )
            return

        # Calculate the cost change
        # Positive usage_change = more usage = more cost = need to reduce credit more
        # Negative usage_change = less usage = less cost = need to increase credit (refund)
        cost_change = usage_change * unit_price

        logger.debug(
            f"Reconciliation credit adjustment for {project.name}: "
            f"usage_change={usage_change:.2f} hours, "
            f"unit_price={unit_price:.4f}, "
            f"cost_change={cost_change:.2f}"
        )

        # Adjust the project credit
        # If cost increased (positive cost_change), reduce credit (subtract from value)
        # If cost decreased (negative cost_change), increase credit (add to value)
        old_credit_value = project_credit.value
        project_credit.value = project_credit.value - decimal.Decimal(cost_change)
        project_credit.save(update_fields=["value"])

        logger.debug(
            f"Adjusted project credit for {project.name} from {old_credit_value:.2f} "
            f"to {project_credit.value:.2f} (change: {-cost_change:.2f})"
        )

    def _reconcile_historical_usage(
        self,
        allocation,
        historical_report,
        month_date: datetime.date,
    ):
        """
        Reconcile historical usage with marketplace ComponentUsage for completed months.

        This method checks if the billing (ComponentUsage) matches the actual usage
        (HistoricalRemoteAllocation) for a completed month. If there's a discrepancy,
        it updates the ComponentUsage which triggers billing adjustments via signals,
        and adjusts project credits accordingly.

        Args:
            allocation: The RemoteAllocation being synced
            historical_report: The HistoricalRemoteAllocation for the month
            month_date: The date representing the month (should be first day of month)
        """
        # Only reconcile completed months
        if not historical_report.is_complete:
            logger.debug(
                f"Skipping reconciliation for {allocation} {month_date.year}-{month_date.month:02d} - month not complete"
            )
            return

        # Get the marketplace resource
        try:
            resource = marketplace_models.Resource.objects.get(scope=allocation)
        except ObjectDoesNotExist:
            logger.warning(
                f"No marketplace Resource found for allocation {allocation} - skipping reconciliation"
            )
            return

        # Get the offering component
        try:
            offering_component = marketplace_models.OfferingComponent.objects.get(
                offering=resource.offering, type="node"
            )
        except ObjectDoesNotExist:
            logger.warning(
                f"No offering component 'node' found for resource {resource} - skipping reconciliation"
            )
            return

        # Resolve the plan period the month being reconciled was billed under,
        # not whichever period happens to be open now. A resource whose plan
        # has changed since — or which has been terminated — has a closed
        # period covering that month, and its ComponentUsage is keyed to it.
        # Looking the usage up under the current period would miss the existing
        # row and add a second one for the same month, which the uniqueness
        # constraint allows because the plan periods differ.
        plan_period = marketplace_utils.get_plan_period_for_billing(
            resource, month_date
        )

        if not plan_period:
            logger.warning(
                f"No active ResourcePlanPeriod found for resource {resource} - skipping reconciliation"
            )
            return

        # Get the billing period
        billing_period = core_utils.month_start(month_date)
        actual_usage = float(historical_report.node_usage)

        # Don't do anything if there's no usage
        if actual_usage <= 0:
            logger.debug(
                f"No usage for {allocation} {month_date.year}-{month_date.month:02d} - skipping reconciliation"
            )
            return

        # Check if ComponentUsage already exists and compare
        existing_usage = marketplace_models.ComponentUsage.objects.filter(
            resource=resource,
            component=offering_component,
            billing_period=billing_period,
            plan_period=plan_period,
        ).first()

        if existing_usage:
            billed_usage = float(existing_usage.usage)
            usage_delta = actual_usage - billed_usage

            # Only reconcile if there's a significant difference (> 0.01 hours)
            if abs(usage_delta) < 0.015:
                logger.debug(
                    f"Usage for {allocation} {month_date.year}-{month_date.month:02d} matches billing "
                    f"(actual: {actual_usage}, billed: {billed_usage})"
                )
                return

            logger.warning(
                f"Usage discrepancy detected for {allocation} {month_date.year}-{month_date.month:02d}: "
                f"actual usage={actual_usage} hours, billed usage={billed_usage} hours, delta={usage_delta} hours"
            )
        else:
            logger.warning(
                f"ComponentUsage missing for {allocation} {month_date.year}-{month_date.month:02d} "
                f"with {actual_usage} hours - will create it"
            )

        # Get or create the ComponentUsage
        component_usage, created = (
            marketplace_models.ComponentUsage.objects.get_or_create(
                resource=resource,
                component=offering_component,
                billing_period=billing_period,
                plan_period=plan_period,
                defaults={
                    "usage": actual_usage,
                    "date": datetime.datetime(
                        month_date.year,
                        month_date.month,
                        15,
                        12,
                        0,
                        0,
                        tzinfo=datetime.UTC,
                    ),
                },
            )
        )

        if created:
            logger.debug(
                f"Created ComponentUsage for {allocation} {month_date.year}-{month_date.month:02d} "
                f"with {actual_usage} hours"
            )
            # New usage created - need to adjust credits by the full amount
            usage_change = actual_usage
        else:
            # Update the usage - this will trigger BillingUsageProcessor.update_invoice_when_usage_is_reported
            old_usage = float(component_usage.usage)
            component_usage.usage = actual_usage
            component_usage.date = datetime.datetime(
                month_date.year,
                month_date.month,
                15,
                12,
                0,
                0,
                tzinfo=datetime.UTC,
            )
            component_usage.save()
            logger.debug(
                f"Updated ComponentUsage for {allocation} {month_date.year}-{month_date.month:02d} "
                f"from {old_usage} to {actual_usage} hours"
            )
            # Calculate the change in usage
            usage_change = actual_usage - old_usage

        # Adjust project credits to reflect the billing change
        self._adjust_project_credits_for_reconciliation(
            resource, month_date, usage_change
        )
