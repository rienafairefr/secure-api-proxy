import dataclasses
import json
import logging
import os
import pathlib
import types
import typing
from collections.abc import Mapping
from typing import Union

from magicproxy.keys import Keys
from magicproxy.plugins import load_plugins
from magicproxy.types import Permission

logger = logging.getLogger(__name__)

DEFAULT_API_ROOT = "https://api.github.com"
DEFAULT_KEYS_LOCATION = "keys"
DEFAULT_PRIVATE_KEY_LOCATION = os.path.join(DEFAULT_KEYS_LOCATION, "private.pem")
DEFAULT_PUBLIC_KEY_LOCATION = os.path.join(DEFAULT_KEYS_LOCATION, "public.pem")
DEFAULT_PUBLIC_CERTIFICATE_LOCATION = os.path.join(
    DEFAULT_KEYS_LOCATION, "public.x509.cer"
)
DEFAULT_PUBLIC_ACCESS = "http://localhost:5000"

DEFAULT_CONFIG = dict(
    api_root=DEFAULT_API_ROOT,
    private_key_location=DEFAULT_PRIVATE_KEY_LOCATION,
    public_key_location=DEFAULT_PUBLIC_KEY_LOCATION,
    public_certificate_location=DEFAULT_PUBLIC_CERTIFICATE_LOCATION,
    public_access=DEFAULT_PUBLIC_ACCESS,
    plugins_location=None,
    scopes={},
    keys=None,
)


@dataclasses.dataclass
class Config:
    api_root: str = DEFAULT_API_ROOT
    private_key_location: Union[str, pathlib.Path] = DEFAULT_PRIVATE_KEY_LOCATION
    public_key_location: Union[str, pathlib.Path] = DEFAULT_PUBLIC_KEY_LOCATION
    public_certificate_location: Union[
        str, pathlib.Path
    ] = DEFAULT_PUBLIC_CERTIFICATE_LOCATION
    public_access: str = DEFAULT_PUBLIC_ACCESS
    plugins_location: Union[str, pathlib.Path] = None
    scopes: typing.Dict[str, Union[Permission, types.ModuleType]] = dataclasses.field(
        default_factory=lambda: {}
    )
    keys: Keys = None

    @property
    def serializable(self):
        def serializable(scope):
            if isinstance(scope, types.ModuleType):
                return str(scope)
            if isinstance(scope, list):
                return [dataclasses.asdict(e) for e in scope]

        return {
            "api_root": self.api_root,
            "private_key_location": self.private_key_location,
            "public_key_location": self.public_key_location,
            "public_certificate_location": self.public_certificate_location,
            "public_access": self.public_access,
            "plugins_location": self.plugins_location,
            "scopes": {k: serializable(scope) for k, scope in self.scopes.items()},
            "keys": "****",
        }


def from_env():
    keys_location = os.environ.get("KEYS_LOCATION")
    if keys_location is not None:
        private_key_location = os.path.join(keys_location, "private.pem")
        public_key_location = os.path.join(keys_location, "public.pem")
        public_certificate_location = os.path.join(keys_location, "public.x509.cer")
    else:
        private_key_location = os.environ.get("PRIVATE_KEY_LOCATION")
        public_key_location = os.environ.get("PUBLIC_KEY_LOCATION")
        public_certificate_location = os.environ.get("PUBLIC_CERTIFICATE_LOCATION")
    return dict(
        public_access=os.environ.get("PUBLIC_ACCESS"),
        api_root=os.environ.get("API_ROOT"),
        private_key_location=private_key_location,
        public_key_location=public_key_location,
        public_certificate_location=public_certificate_location,
    )


def from_file(config_file=None):
    if config_file is None:
        return {}
    try:
        config_string = open(config_file, "r", encoding="utf-8").read()
    except IOError:
        raise RuntimeError("I/O error, config file should be readable")
    try:
        config = json.loads(config_string)
    except ValueError:
        raise RuntimeError("config file should be a valid JSON file")

    scopes = config.get("scopes", {})
    for scope_key in scopes:
        scope_elements = []
        for scope_element in scopes[scope_key]:
            scope_elements.append(parse_permission(scope_element))
        scopes[scope_key] = scope_elements
    plugins_location = config.get("plugins_location")
    if plugins_location:
        scopes.update(**load_plugins(plugins_location))

    keys_location = config.get("keys_location")
    if keys_location is not None:
        private_key_location = os.path.join(keys_location, "private.pem")
        public_key_location = os.path.join(keys_location, "public.pem")
        public_certificate_location = os.path.join(keys_location, "public.x509.cer")
    else:
        private_key_location = config.get("private_key_location")
        public_key_location = config.get("public_key_location")
        public_certificate_location = config.get("public_certificate_location")
    return dict(
        api_root=config.get("api_root"),
        private_key_location=private_key_location,
        public_key_location=public_key_location,
        public_certificate_location=public_certificate_location,
        public_access=config.get("public_access"),
        plugins_location=plugins_location,
        scopes=scopes,
    )


def load_config(_load_keys=True, **kwargs):
    file_config = from_file(os.environ.get("CONFIG_FILE"))
    env_config = from_env()
    kwargs_config = kwargs

    config = {}
    for field in dataclasses.fields(Config):
        if kwargs_config.get(field.name) is not None:
            config[field.name] = kwargs[field.name]
        elif env_config.get(field.name) is not None:
            config[field.name] = env_config[field.name]
        elif file_config.get(field.name) is not None:
            config[field.name] = file_config[field.name]
        else:
            config[field.name] = DEFAULT_CONFIG[field.name]

    config = Config(**config)

    if _load_keys:
        config.keys = Keys.from_files(
            config.private_key_location, config.public_certificate_location
        )

    logger.debug("config %s", json.dumps(config.serializable, indent=2))

    return config


def parse_permission(element: Union[str, Mapping]) -> Permission:
    logging.debug("parsing permission from %s", element)
    if isinstance(element, str):
        try:
            method, path = element.split(" ", 1)
            return Permission(method=method, path=path)
        except ValueError as e:
            raise ValueError('a scope string should be a "METHOD path_regex"') from e
    elif isinstance(element, Mapping):
        if "method" in element and "path" in element:
            return Permission(method=element["method"], path=element["path"])
        else:
            raise ValueError(
                "a scope mapping should be a mapping with method, path keys"
            )
