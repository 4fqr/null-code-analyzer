"""
INTENTIONALLY VULNERABLE CODE - FOR TESTING ONLY
Insecure deserialization vulnerabilities
"""

import pickle
import yaml
import marshal


def vulnerable_deserialize_v1(user_data):
    """Pickle deserialization from untrusted source"""
    # VULNERABLE: pickle.loads with user data
    obj = pickle.loads(user_data)
    return obj


def vulnerable_deserialize_v2(yaml_data):
    """YAML deserialization without safe loader"""
    # VULNERABLE: yaml.load without Loader argument
    config = yaml.load(yaml_data)
    return config


def vulnerable_deserialize_v3(serialized):
    """Marshal deserialization"""
    # VULNERABLE: marshal.loads with user input
    code = marshal.loads(serialized)
    return code


# SAFE EXAMPLE
def safe_deserialize_v1(user_data):
    """Safe JSON deserialization"""
    import json
    
    # SAFE: JSON doesn't execute code
    obj = json.loads(user_data)
    return obj


def safe_deserialize_v2(yaml_data):
    """Safe YAML deserialization"""
    # SAFE: yaml.safe_load or FullLoader
    config = yaml.load(yaml_data, Loader=yaml.SafeLoader)
    return config
