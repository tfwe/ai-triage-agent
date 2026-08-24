# import json
# from pydantic import ValidationError
#
# def parse_generic_logs(file_path, schema_model):
#     valid_logs = []
#     with open(file_path, 'r') as f:
#         for line in f:
#             try:
#                 raw_log = json.loads(line)
#                 validated_log = schema_model(**raw_log)
#                 valid_logs.append(validated_log)
#             except ValidationError:
#                 # Drop noise silently
#                 continue
#     return valid_logs
