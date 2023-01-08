""" THIS IS AN AUTOMATICALLY GENERATED FILE!"""
from __future__ import print_function
import json
from engine import primitives
from engine.core import requests
from engine.errors import ResponseParsingException
from engine import dependencies

_projects__id__repository_commits_post_last_pipeline_sha = dependencies.DynamicVariable("_projects__id__repository_commits_post_last_pipeline_sha")

def parse_projectsidrepositorycommitspost(data):
    """ Automatically generated response parser """
    # Declare response variables
    temp_7262 = None
    # Parse the response into json
    try:
        data = json.loads(data)
    except Exception as error:
        raise ResponseParsingException("Exception parsing response, data was not valid json: {}".format(error))

    # Try to extract each dynamic object


    try:
        temp_7262 = str(data["last_pipeline"]["sha"])
    except Exception as error:
        # This is not an error, since some properties are not always returned
        pass


    # If no dynamic objects were extracted, throw.
    if not (temp_7262):
        raise ResponseParsingException("Error: all of the expected dynamic objects were not present in the response.")

    # Set dynamic variables
    if temp_7262:
        dependencies.set_variable("_projects__id__repository_commits_post_last_pipeline_sha", temp_7262)

req_collection = requests.RequestCollection([])
# Endpoint: /projects/{id}/repository/commits, method: Get
request = requests.Request([
    primitives.restler_static_string("GET "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("?"),
    primitives.restler_static_string("ref_name="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("since="),
    primitives.restler_fuzzable_datetime("2019-06-26T20:20:39+00:00", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("until="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("path="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("all="),
    primitives.restler_fuzzable_bool("true"),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("with_stats="),
    primitives.restler_fuzzable_bool("true"),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("first_parent="),
    primitives.restler_fuzzable_bool("true"),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("order="),
    primitives.restler_fuzzable_group("fuzzable_group_tag", ['default','topo'] , default_enum="default" ,quoted=False),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/repository/commits"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/repository/commits, method: Post
request = requests.Request([
    primitives.restler_static_string("POST "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("?"),
    primitives.restler_static_string("branch="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("commit_message="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("start_branch="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("start_sha="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("start_project="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("author_email="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("author_name="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("stats="),
    primitives.restler_fuzzable_bool("true"),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("force="),
    primitives.restler_fuzzable_bool("true"),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_static_string("Content-Type: application/json\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),
    primitives.restler_static_string("["),
    primitives.restler_static_string("""
    {
        "action":"""),
    primitives.restler_fuzzable_group("fuzzable_group_tag", ['create','delete','move','update','chmod']  ,quoted=True),
    primitives.restler_static_string(""",
        "file_path":"""),
    primitives.restler_fuzzable_string("fuzzstring", quoted=True),
    primitives.restler_static_string(""",
        "previous_path":"""),
    primitives.restler_fuzzable_string("fuzzstring", quoted=True),
    primitives.restler_static_string(""",
        "content":"""),
    primitives.restler_fuzzable_string("fuzzstring", quoted=True),
    primitives.restler_static_string(""",
        "encoding":"""),
    primitives.restler_fuzzable_group("fuzzable_group_tag", ['base64','text'] , default_enum="text" ,quoted=True),
    primitives.restler_static_string(""",
        "last_commit_id":"""),
    primitives.restler_fuzzable_string("fuzzstring", quoted=True),
    primitives.restler_static_string(""",
        "execute_filemode":"""),
    primitives.restler_fuzzable_bool("true"),
    primitives.restler_static_string("""
    }]"""),
    primitives.restler_static_string("\r\n"),
    
    {
        'post_send':
        {
            'parser': parse_projectsidrepositorycommitspost,
            'dependencies':
            [
                _projects__id__repository_commits_post_last_pipeline_sha.writer()
            ]
        }
    },

],
requestId="/projects/{id}/repository/commits"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/repository/commits/{sha}, method: Get
request = requests.Request([
    primitives.restler_static_string("GET "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string(_projects__id__repository_commits_post_last_pipeline_sha.reader()),
    primitives.restler_static_string("?"),
    primitives.restler_static_string("stats="),
    primitives.restler_fuzzable_bool("true"),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/repository/commits/{sha}"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/repository/commits/{sha}/refs, method: Get
request = requests.Request([
    primitives.restler_static_string("GET "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string(_projects__id__repository_commits_post_last_pipeline_sha.reader()),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("refs"),
    primitives.restler_static_string("?"),
    primitives.restler_static_string("type="),
    primitives.restler_fuzzable_group("fuzzable_group_tag", ['branch','tag','all'] , default_enum="all" ,quoted=False),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/repository/commits/{sha}/refs"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/repository/commits/{sha}/cherry_pick, method: Post
request = requests.Request([
    primitives.restler_static_string("POST "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string(_projects__id__repository_commits_post_last_pipeline_sha.reader()),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("cherry_pick"),
    primitives.restler_static_string("?"),
    primitives.restler_static_string("dry_run="),
    primitives.restler_fuzzable_bool("true"),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/repository/commits/{sha}/cherry_pick"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/repository/commits/{sha}/revert, method: Post
request = requests.Request([
    primitives.restler_static_string("POST "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string(_projects__id__repository_commits_post_last_pipeline_sha.reader()),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("revert"),
    primitives.restler_static_string("?"),
    primitives.restler_static_string("dry_run="),
    primitives.restler_fuzzable_bool("true"),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/repository/commits/{sha}/revert"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/repository/commits/{sha}/diff, method: Get
request = requests.Request([
    primitives.restler_static_string("GET "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string(_projects__id__repository_commits_post_last_pipeline_sha.reader()),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("diff"),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/repository/commits/{sha}/diff"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/repository/commits/{sha}/comments, method: Get
request = requests.Request([
    primitives.restler_static_string("GET "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string(_projects__id__repository_commits_post_last_pipeline_sha.reader()),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("comments"),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/repository/commits/{sha}/comments"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/repository/commits/{sha}/discussions, method: Get
request = requests.Request([
    primitives.restler_static_string("GET "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string(_projects__id__repository_commits_post_last_pipeline_sha.reader()),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("discussions"),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/repository/commits/{sha}/discussions"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/repository/commits/{sha}/statuses, method: Get
request = requests.Request([
    primitives.restler_static_string("GET "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string(_projects__id__repository_commits_post_last_pipeline_sha.reader()),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("statuses"),
    primitives.restler_static_string("?"),
    primitives.restler_static_string("ref="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("stage="),
    primitives.restler_fuzzable_group("fuzzable_group_tag", ['build','test','deploy'] , default_enum="test" ,quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("name="),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("all="),
    primitives.restler_fuzzable_bool("true"),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("page="),
    primitives.restler_fuzzable_int("1"),
    primitives.restler_static_string("&"),
    primitives.restler_static_string("per_page="),
    primitives.restler_fuzzable_int("1"),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/repository/commits/{sha}/statuses"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/statuses/{sha}, method: Post
request = requests.Request([
    primitives.restler_static_string("POST "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("statuses"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/statuses/{sha}"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/repository/commits/{sha}/merge_requests, method: Get
request = requests.Request([
    primitives.restler_static_string("GET "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string(_projects__id__repository_commits_post_last_pipeline_sha.reader()),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("merge_requests"),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/repository/commits/{sha}/merge_requests"
)
req_collection.add_request(request)

# Endpoint: /projects/{id}/repository/commits/{sha}/signature, method: Get
request = requests.Request([
    primitives.restler_static_string("GET "),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("api"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("v4"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("projects"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_string("fuzzstring", quoted=False),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("repository"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("commits"),
    primitives.restler_static_string("/"),
    primitives.restler_static_string(_projects__id__repository_commits_post_last_pipeline_sha.reader()),
    primitives.restler_static_string("/"),
    primitives.restler_static_string("signature"),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: 10.214.242.55\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/projects/{id}/repository/commits/{sha}/signature"
)
req_collection.add_request(request)
