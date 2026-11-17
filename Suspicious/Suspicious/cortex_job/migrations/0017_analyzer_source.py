from django.db import migrations, models


def mark_provider_rows(apps, schema_editor):
    apps.get_model("cortex_job", "Analyzer").objects.filter(
        analyzer_cortex_id__startswith="provider:"
    ).update(source="ai_model")


class Migration(migrations.Migration):

    dependencies = [
        ("cortex_job", "0016_analyzerreport_pre_allowlist"),
    ]

    operations = [
        migrations.AddField(
            model_name="analyzer",
            name="source",
            field=models.CharField(
                db_index=True, default="cortex", max_length=100,
                help_text="Name of the connector that owns this analyzer.",
            ),
        ),
        migrations.RunPython(mark_provider_rows, migrations.RunPython.noop),
    ]
