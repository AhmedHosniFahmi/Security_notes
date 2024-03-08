from cryptography.fernet import Fernet
key = b"6oRRYudAtrVSTuWuIwYs_3jpD4RjzAfXRSYcouKeWcM="
secret = b"gAAAAABh2ufi-h5nTOVv7H-H3IEhlq16XjauQEdGseZMWR-8wioAygIjlp6eeVMVED9OxHRfA8xi0Smls_EgCaG_j4fs0AIP4tEczNydYqdsaejMO0NvpFXt7P0vYtdjDTJ_Vc2yM-N4gLPH4SgQTJi-Cfn9uuOBVQ=="

enc = Fernet(key)
deced = enc.decrypt(secret)
print(deced)