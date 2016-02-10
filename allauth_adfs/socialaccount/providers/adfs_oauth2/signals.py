import django.dispatch

extract_uid_signal = django.dispatch.Signal(providing_args=["data"])
extract_common_fields_signal = django.dispatch.Signal(providing_args=["data"])
extract_email_addresses_signal = django.dispatch.Signal(providing_args=["data"])