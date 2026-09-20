from __future__ import annotations

import sys
import types

from auth_adapter import build_external_authenticator


def test_external_sdk_adapter_uses_runtime_configuration(monkeypatch) -> None:
    module = types.ModuleType("fake_external_auth")

    class Provider:
        def __init__(self, **kwargs):
            self.options = kwargs

        def sign_in(self):
            return {"token": "session"}

        def profile(self):
            return {"name": "test-user"}

    module.Provider = Provider
    monkeypatch.setitem(sys.modules, module.__name__, module)

    authenticator = build_external_authenticator(
        module_name=module.__name__,
        factory_name="Provider",
        login_method="sign_in",
        user_info_method="profile",
        constructor_kwargs={"headless": True},
    )

    context = authenticator.authenticate()

    assert context.session == {"token": "session"}
    assert context.user_info == {"name": "test-user"}
