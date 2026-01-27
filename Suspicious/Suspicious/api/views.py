from django.db.models import Sum
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, NotFound, APIException
from rest_framework.response import Response
from rest_framework import generics
from django_filters.rest_framework import DjangoFilterBackend

from drf_spectacular.utils import extend_schema, OpenApiParameter

from case_handler.models import Case
from mail_feeder.models import MailArchive
from dashboard.models import (
    MonthlyCasesSummary,
    UserCasesMonthlyStats,
    MonthlyReporterStats,
    TotalCasesStats,
)
from knox.models import AuthToken
from .serializers import (
    MonthlyCasesSummarySerializer,
    UserCasesMonthlyStatsSerializer,
    MonthlyReporterStatsSerializer,
    TotalCasesStatsSerializer,
)
from .filters import MonthlyCasesSummaryFilter, MonthlyReporterStatsFilter, TotalCasesStatsFilter
from .storage import StorageClient
from .mixins import MonthYearQueryMixin
from .audit import log_cert_download
from django.utils import timezone
import json
import io
import zipfile
from django.http import StreamingHttpResponse
import os
import logging
from minio.error import S3Error

from django.conf import settings
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone

from rest_framework.permissions import AllowAny

import hashlib
import requests

from score_process.score_utils.thehive.challenge import ChallengeToTheHiveService
from score_process.score_utils.send_mail.service import MailNotificationService

from django.contrib.auth import get_user_model

from case_handler.models import Case
from api.models import CaseChallengeToken


User = get_user_model()



# ---------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------

ALLOWED_DOWNLOAD_GROUPS = {"Admin", "CERT"}
CONFIG_PATH = os.environ.get("SUSPICIOUS_SETTINGS_PATH", "/app/settings.json")
logger = logging.getLogger(__name__)
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

thehive_config = config.get("thehive", {})

CHALLENGE_REDIRECT_URL = "https://suspicious-domain.com/submissions"

# Put the real Suspicious API endpoint here (not the GitHub repo URL).
SUSPICIOUS_API_URL = getattr(settings, "SUSPICIOUS_API_URL", "https://github.com/thalesgroup-cert/suspicious")


class CaseChallengeOneTimeLinkView(APIView):
    """
    GET /api/cases/{case_id}/challenge?token=ONE_TIME_TOKEN

    - No auth required
    - Token is single-use, case-bound, expirable
    - Always redirects to CHALLENGE_REDIRECT_URL (no validity oracle)
    """
    permission_classes = [AllowAny]
    authentication_classes = []  # ensure DRF doesn't try to authenticate

    def get(self, request, case_id: int):
        raw = request.query_params.get("token")
        if not raw:
            return redirect(CHALLENGE_REDIRECT_URL)

        # Case existence: you can choose to not reveal this either.
        # But we still redirect; no body/status differences.
        case = get_object_or_404(Case.objects.select_related("reporter"), pk=case_id)

        token_hash = _hash_raw_token(raw)
        now = timezone.now()

        token_obj = None

        # Consume token exactly once (race-safe)
        with transaction.atomic():
            token_obj = (
                CaseChallengeToken.objects
                .select_for_update()
                .filter(case=case, token_hash=token_hash)
                .first()
            )
            if not token_obj:
                return redirect(CHALLENGE_REDIRECT_URL)

            if token_obj.used_at is not None or now >= token_obj.expires_at:
                return redirect(CHALLENGE_REDIRECT_URL)

            # Mark used immediately to prevent replay (even if downstream fails)
            token_obj.used_at = now
            # optional audit fields if present on your model:
            if hasattr(token_obj, "used_ip"):
                token_obj.used_ip = request.META.get("REMOTE_ADDR")
            if hasattr(token_obj, "used_user_agent"):
                token_obj.used_user_agent = (request.META.get("HTTP_USER_AGENT") or "")[:2000]

            update_fields = ["used_at"]
            if hasattr(token_obj, "used_ip"):
                update_fields.append("used_ip")
            if hasattr(token_obj, "used_user_agent"):
                update_fields.append("used_user_agent")

            token_obj.save(update_fields=update_fields)

        # External call + Case updates (token already consumed => at-most-once)
        self._call_suspicious_and_update_case(case=case, token_obj=token_obj)

        # Update stats + notify (best-effort, should not block redirect)
        try:
            if hasattr(case, "reporter") and case.reporter_id:
                _update_case_challenge_stats(case.reporter)
            _notify_case_challenge(case, logger)
        except Exception:
            logger.exception("Challenge notify/stats failed for case %s", case.id)

        return redirect(CHALLENGE_REDIRECT_URL)

    def _call_suspicious_and_update_case(self, *, case: Case, token_obj):
        payload = {
            "case_id": case.pk,
            "action": "challenge",
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        try:
            resp = requests.post(
                SUSPICIOUS_API_URL,
                json=payload,
                headers=headers,
                timeout=(3.05, 10),
            )

            # optional audit fields
            if hasattr(token_obj, "api_status_code"):
                token_obj.api_status_code = resp.status_code

            try:
                data = resp.json()
            except ValueError:
                data = {"raw": resp.text[:5000]}

            if hasattr(token_obj, "api_response"):
                token_obj.api_response = data

            if 200 <= resp.status_code < 300:
                # Required Case state updates
                case.is_challenged = True
                case.challenged_result = data
                case.status = "Challenged"
                case.save(update_fields=["is_challenged", "challenged_result", "status"])
            else:
                if hasattr(token_obj, "api_error"):
                    token_obj.api_error = f"Non-2xx from external API: {resp.status_code}"

        except requests.RequestException as e:
            if hasattr(token_obj, "api_error"):
                token_obj.api_error = f"{e.__class__.__name__}: {str(e)[:2000]}"
        finally:
            # save token audit best-effort
            try:
                update_fields = []
                for f in ("api_status_code", "api_response", "api_error"):
                    if hasattr(token_obj, f):
                        update_fields.append(f)
                if update_fields:
                    token_obj.save(update_fields=update_fields)
            except Exception:
                logger.exception("Failed saving challenge token audit for case %s", case.id)

def _hash_raw_token(raw_token: str) -> str:
    """
    SHA256(SECRET_KEY || raw_token) hex digest.
    'Pepper' via SECRET_KEY prevents offline brute force if DB leaks.
    """
    h = hashlib.sha256()
    h.update((settings.SECRET_KEY + raw_token).encode("utf-8"))
    return h.hexdigest()


def _update_case_challenge_stats(user):
    now = timezone.now()
    stats, _ = UserCasesMonthlyStats.objects.get_or_create(
        user=user,
        month=now.strftime("%m"),
        year=now.year,
        defaults={"challenged_cases": 0, "total_cases": 0},
    )
    stats.challenged_cases += 1
    stats.save(update_fields=["challenged_cases"])


def _notify_case_challenge(case: Case, logger):
    """
    “Notify process by hand” equivalent to your CaseChallengeService.notify().
    Adjust import paths/names to your existing TheHive/email notification services.
    """
    send_to_thehive = thehive_config.get("enabled", False)
    reporter = getattr(case, "reporter", None)
    reporter_name = getattr(reporter, "username", "unknown")

    mail_header = f"Case ID {case.id} challenged by {reporter_name}"
    logger.info(
        "Notifying about challenge for case ID %s. Send to TheHive: %s",
        case.id, send_to_thehive
    )

    if send_to_thehive:
        logger.info("Sending challenge notification to TheHive for case ID %s", case.id)
        ChallengeToTheHiveService(case, None, mail_header).send_to_thehive()
        logger.info("Challenge notification sent to TheHive for case ID %s", case.id)
        return

    cert_users = User.objects.filter(groups__name="CERT", is_active=True).exclude(email="")
    for cert_user in cert_users:
        ChallengeToTheHiveService(case, cert_user, mail_header).send()



class StorageUnavailable(APIException):
    status_code = 503
    default_detail = "Storage backend unavailable"
    default_code = "storage_unavailable"


def load_minio_config(path: str):
    try:
        with open(path) as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        logger.warning("Settings file not found: %s", path)
        return None
    except json.JSONDecodeError:
        logger.warning("Settings file contains invalid JSON: %s", path)
        return None

    return config.get("minio")


minio_config = load_minio_config(CONFIG_PATH)
# Generate API Key
def generate_api_key(user, expiration):
    expiry = timezone.timedelta(days=expiration)
    token_instance, raw_key = AuthToken.objects.create(user=user, expiry=expiry)
    return raw_key, token_instance

def user_can_download(user) -> bool:
    return user.groups.filter(name__in=ALLOWED_DOWNLOAD_GROUPS).exists()


# ---------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------
class DownloadCaseArchiveView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, case_id: int):
        if not user_can_download(request.user):
            raise PermissionDenied("Not authorized")

        if not minio_config:
            raise StorageUnavailable("Storage backend not configured")

        case = self._get_case(case_id)
        archive = self._get_archive(case)

        storage = StorageClient(minio_config)
        if not storage.client:
            raise StorageUnavailable("Storage backend unavailable")

        try:
            objects = storage.client.list_objects(archive.bucket_name, recursive=True)
        except S3Error:
            raise NotFound("Bucket not found")

        def zip_stream():
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for obj in objects:
                    try:
                        data = storage.client.get_object(archive.bucket_name, obj.object_name)
                        zip_file.writestr(obj.object_name, data.read())
                        data.close()
                    except S3Error:
                        continue
            buf.seek(0)
            yield from buf

        response = StreamingHttpResponse(
            zip_stream(),
            content_type="application/zip"
        )
        response['Content-Disposition'] = f'attachment; filename="case_{case.pk}.zip"'

        log_cert_download(
            user=request.user,
            case_id=case.pk,
            object_name=f"case_{case.pk}.zip",
            ip=request.META.get("REMOTE_ADDR"),
        )

        return response

    @staticmethod
    def _get_case(case_id: int) -> Case:
        try:
            return Case.objects.select_related(
                "fileOrMail__mail"
            ).get(pk=case_id)
        except Case.DoesNotExist:
            raise NotFound("Case not found")

    @staticmethod
    def _get_archive(case: Case) -> MailArchive:
        if not case.fileOrMail or not case.fileOrMail.mail:
            raise NotFound("No mail linked to case")

        archive = MailArchive.objects.filter(
            mail=case.fileOrMail.mail
        ).first()

        if not archive or not archive.bucket_name:
            raise NotFound("Archive not found")

        return archive

class MonthlyCasesSummaryListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = MonthlyCasesSummary.objects.all()
    serializer_class = MonthlyCasesSummarySerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = MonthlyCasesSummaryFilter


class MonthlyReporterStatsListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = MonthlyReporterStats.objects.all()
    serializer_class = MonthlyReporterStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = MonthlyReporterStatsFilter


class TotalCasesStatsListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = TotalCasesStats.objects.all()
    serializer_class = TotalCasesStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = TotalCasesStatsFilter


class UserCasesMonthlyStatsListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = UserCasesMonthlyStats.objects.all()
    serializer_class = UserCasesMonthlyStatsSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["user", "month", "year"]


class UserCasesMonthlyStatsDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    queryset = UserCasesMonthlyStats.objects.all()
    serializer_class = UserCasesMonthlyStatsSerializer

# ---------------------------------------------------------------------
# Monthly aggregation (with mixin + OpenAPI)
# ---------------------------------------------------------------------

class MonthlyCasesSummaryAggregateView(
    MonthYearQueryMixin,
    APIView,
):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter("month", int, OpenApiParameter.QUERY),
            OpenApiParameter("year", int, OpenApiParameter.QUERY),
        ],
        responses=MonthlyCasesSummarySerializer(many=True),
        description="Aggregate case stats for a given month/year",
    )
    def get(self, request):
        month, year = self.get_month_year()

        data = MonthlyCasesSummary.objects.filter(
            creation_date__month=month,
            creation_date__year=year,
        ).values("user__username", "creation_date__month", "creation_date__year").aggregate(
            suspicious_cases=Sum("suspicious_cases"),
            inconclusive_cases=Sum("inconclusive_cases"),
            failure_cases=Sum("failure_cases"),
            dangerous_cases=Sum("dangerous_cases"),
            safe_cases=Sum("safe_cases"),
            challenged_cases=Sum("challenged_cases"),
            allow_listed_cases=Sum("allow_listed_cases"),
            uncategorized_cases=Sum("uncategorized_cases"),
            spam_cases=Sum("spam_cases"),
            newsletter_cases=Sum("newsletter_cases"),
            classic_phishing_cases=Sum("classic_phishing_cases"),
            clone_cases=Sum("clone_cases"),
            blackmail_cases=Sum("blackmail_cases"),
            whaling_cases=Sum("whaling_cases"),
            internal_cases=Sum("internal_cases"),
            external_cases=Sum("external_cases"),
        )
        return Response(data)


class UserCasesMonthlyStatsAggregateView(
    MonthYearQueryMixin,
    APIView,
):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter("month", int, OpenApiParameter.QUERY),
            OpenApiParameter("year", int, OpenApiParameter.QUERY),
        ],
        responses=UserCasesMonthlyStatsSerializer(many=True),
        description="Aggregate user case statistics",
    )
    def get(self, request):
        month, year = self.get_month_year()

        data = (
            UserCasesMonthlyStats.objects
            .filter(month=month, year=year)
            .values("user__username", "creation_date__month", "creation_date__year")
            .annotate(
                total_cases=Sum("total_cases"),
                total_safe=Sum("safe_cases"),
                total_dangerous=Sum("dangerous_cases"),
                total_suspicious=Sum("suspicious_cases"),
                total_inconclusive=Sum("inconclusive_cases"),
                total_failure=Sum("failure_cases"),
                total_uncategorized=Sum("uncategorized_cases"),
                total_spam=Sum("spam_cases"),
                total_newsletter=Sum("newsletter_cases"),
                total_classic_phishing=Sum("classic_phishing_cases"),
                total_clone=Sum("clone_cases"),
                total_blackmail=Sum("blackmail_cases"),
                total_whaling=Sum("whaling_cases"),
                total_internal=Sum("internal_cases"),
                total_external=Sum("external_cases"),
                total_challenged=Sum("challenged_cases"),
                total_allow_listed=Sum("allow_listed_cases"),
            )
        )

        return Response(list(data))
