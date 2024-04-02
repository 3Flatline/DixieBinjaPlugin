
import gotrue.errors
import logging
import requests
import json
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from supabase import create_client, Client
import sys
import time
import os
# import tiktoken
from typing import List
import tempfile

CLI_VERSION = "v1.2"

C_MODEL_ENDINGS = [
    ".c",
    ".cc",
    ".cpp",
    ".m",
]
APPSEC_MODEL_ENDINGS = [".php", ".go", ".py", ".rb", ".js", ".java", ".html"]
MAX_FILE_UPLOAD_SIZE = 1024 * 1024 * 10
# DEV
# API_URL_BASE = "https://krjndzi2kb.execute-api.us-east-1.amazonaws.com/v1/"
# PROD
# API_URL_BASE = 'https://api2.3flatline.ai'
API_URL_BASE = 'http://54.226.128.229'


logging.disable(sys.maxsize)

class DixieAPI:
    POSTGRES_PUBLIC_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imh1bXFwempucnFuY2pwZmRydGhxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MDM4NTkxMzQsImV4cCI6MjAxOTQzNTEzNH0.y0DIlnd6Eg4ZtC2ieTzoa9102klz8hkXWUjpWpMNHIs'
    POSTGRES_URL = "https://humqpzjnrqncjpfdrthq.supabase.co"
    """Class to handle all API calls to 3Flatline Dixie API."""
    
    def __init__(self) -> None:
        
        self.auth_info = {}
        self.supabase_client: Client = create_client(self.POSTGRES_URL, self.POSTGRES_PUBLIC_KEY)
    
    def authenticate(self, email: str, password: str) -> None:
        """Authenticate user with email and password."""
        try:
            data = self.supabase_client.auth.sign_in_with_password(
                {"email": email,
                "password": password}
            )
            self.supabase_client.postgrest.auth(data.session.access_token)

        except gotrue.errors.AuthApiError as exc:
            print(
                f"Error encountered during login: {type(exc).__name__}: {str(exc)}"
            )
            print(
                "If this is repeated or unexpected, please contact support@3flatline.ai"
            )
            return
        # TODO: Check for message needing verification or password change or something.
        access_token = data.session.access_token
        refresh_token = data.session.refresh_token
        self.auth_info = {
            "auth_token": access_token,
            "refresh_token": refresh_token,
        }
        # print("Log in success")

    def refresh_auth(self):
        """Refresh authentication with the server."""
        if not self.supabase_client:
            print("No login credentials found. Have you authenticated already?")
            return
        data = self.supabase_client.auth.refresh_session()
        self.auth_info = {
            "auth_token": data.session.access_token,
            "refresh_token": data.session.refresh_token,
        }
    
    def check_response_error(self, response, expected_code=None) -> bool:
        """Check and output information for an error repsonse."""
        # print(type(response.status_code))
        # print(response.content)
        if expected_code:
            if response.status_code == expected_code:
                return True
            else:
                return False
        if response.status_code == 200:
            return True
        if response.status_code == 401:
            print(
                "ERROR: received 'Unauthorized' message.  Have you authenticated to the server?"
            )
            print(
                "To authenticate try the command: authenticate -u <username> -p <password>"
            )
            return False
        if response.status_code == 403:
            if "token" in str(response.content):
                print(
                    "ERROR: Estimated token length of file exceeds monthly available token limit."
                )
            elif "length exceeds maximum file size." in str(response.content):
                print(
                    "ERROR: Estimated token length of file exceeds maximum file size."
                )
            else:
                print(
                    "ERROR: Your account is not authorized to conduct this action:"
                )
                print(response.content)
            return False
        print(f"Error encountered: result status code was {response.status_code} and content {response.content}")
        return False
    
    def create_task(self, file_ptr: tempfile._TemporaryFileWrapper, description, vulns, fixes) -> str:
        """Create a task on the server."""
        
        self.refresh_auth()
        paths_to_analyze = []
        retry_paths = []
        with requests.session() as session:
            retry_strategy = Retry(
                total=5,
                backoff_factor=2,
                status_forcelist=[500, 502, 503, 504],
            )
            session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
            # try:
            #     encoding = tiktoken.get_encoding("cl100k_base")
            #     token_estimate = 0
            #     for line in file_ptr.readlines():
            #         token_estimate += len(encoding.encode(line))
            #     print(f"Estimated file token length: {token_estimate}")
            # except FileNotFoundError:
            #     print(
            #         f"Couldn't find file, verify the file exists and path is correct."
            #     )
            #     return {}
            # print("Creating task entry in database.")
            result = session.post(
                f"{API_URL_BASE}/tasks",
                headers={
                    "Authorization": self.auth_info.get("auth_token"),
                    # "x-api-key": self.auth_info.get("user_api_key"),
                    "cli-version": CLI_VERSION,
                    "token-estimate": "0",
                    "filepath": file_ptr.name,
                    "vulns": str(vulns),
                },
                json={
                    "filepath": file_ptr.name,
                    "token-estimate": 0,
                },
                # verify=False,
            )
            # print(result.content)
            if (
                result.status_code == 403
                and "length exceeds maximum file size." in str(result.content)
            ):
                print(
                    "ERROR: Estimated token length of file exceeds maximum file size.  Skipping."
                )
                return {}
            elif not self.check_response_error(result):
                print("Error during task creation on AWS server.")
                # print(result.status_code)
                # print(result.content)
                return {}
            result_json = result.json()
            # FastAPI copy pasta error, TODO: fix actual return code.
            if result_json.get('statusCode') != 200:
                print(f"Error during task creation on AWS server: {result_json.get('body')}")
                return
            try:
                body = result_json.get("body")
            except TypeError:
                print(f"Unable to create task on the server due to unexpected response format Please report this to support@3flatline.ai: {result_json}")
            new_task_id = body.get("task_id")
            signed_url = body.get("signed_url")

            print(
                f"Created task entry in database for task id: {new_task_id}, uploading for analysis."
            )
            # converted_result = result.json()
            # s3_auth_data = converted_result["url_info"]
            # headers = s3_auth_data.get("fields")
            try:
                file_ptr.seek(0)
                response = session.put(
                    signed_url,
                    files={"file": file_ptr},
                )
                # print(response.status_code)
                # print(response.content)
                if self.check_response_error(response, expected_code=200):
                    print("Successfully uploaded file to server.")
                else:
                    print(
                        "Error uploading to server, delete task entry and try again with full path."
                    )
                    print(
                        f"To delete task entry run: delete {new_task_id}"
                    )
                    return {}
            except FileNotFoundError:
                print(
                    f"Couldn't find file, verify the file exists and path is correct."
                )
                return {}
            # Kick off analysis
            result = requests.post(
                    f"{API_URL_BASE}/tasks/{new_task_id}",
                        headers={
                            "Authorization": self.auth_info.get("auth_token"),
                            "cli_version": CLI_VERSION,
                        },
                        # verify=False
                )
            # print(result.status_code)
            # print(result.content)
            if not self.check_response_error(result):
                print("Error during activation of task.")
                # print(result.status_code)
                # print(result.content)
                return {}
            print(f"Successfully activated task {new_task_id}.")
            return new_task_id
    
    def list_tasks(self, task_ids: list = [], download_path: str = "", markdown: bool = False) -> dict:
        """List all code scanning tasks in your account (-s for search by task id)"""

        result_status = {}
        if task_ids:
            length = len(task_ids)
            for i in range(0, length, 20):
                api_response = self.supabase_client.table('tasks').select("*").in_('task_id', task_ids[i:i+20]).execute()
                for entry in api_response.data:
                    # print(entry)
                    result_status.update({entry.get('task_id'): entry})
                # print(result_status)
        else:
            api_response = self.supabase_client.table('tasks').select("*").execute()
            for entry in api_response.data:
                # print(entry)
                result_status.update({entry.get('task_id'): entry})
            # print(result_status)
            #TODO: Fix for api_response
        if not result_status:
            print("No existing tasks to pull status for.")
            return result_status

        # print("Results:")
        # print(json.dumps(result_status, indent=5))
        return result_status

    def format_markdown(self, result_dict) -> str:
        # print("Converting to markdown.")
        # print(result_dict)
        task_id = result_dict.get("task_id")
        self.convert_list_markdown(result_dict.get("models"))
        filepath = result_dict.get("filepath")
        created_time = result_dict.get("created_at")
        results = result_dict.get("results")
        # There are two scenarios we need to check for.
        # 1) if run isn't finished, no entry in results or it is a string.
        # 2) if run is finished, could be string or list, but list might have "None" if no bugs.
        description = ""
        markdown_vuln_string = ""
        if isinstance(results, list) and results:
            result_entry = results[0]
            if result_entry:
                # Parse out description safely
                description = result_entry.get("code_description")
                if description:
                    # Temporary for version migration on backend
                    try:
                        description = description.get('description')
                    except AttributeError:
                        # Leave current description var as it is correct
                        pass
                else:
                    description = "No description provided."
                # description = result_entry.get("code_description").get("description")
                # split_description = description.split("Code Description:")
                # if len(split_description) > 1:
                #     description = split_description[1]
                bugs_list = result_entry.get("bugs")
                if bugs_list:
                    for entry in bugs_list:
                        markdown_vuln_string+=f"{entry}\n"
        markdown_string = f"""# {filepath.strip('.c')}

| Field | Content |
| --- | ----------- |
| Task ID | {task_id} |
| Task Submitted | {created_time} |

## Code Description

{description}

## Vulnerabilities Detected: 

{markdown_vuln_string}

"""
        return markdown_string

    def convert_list_markdown(self, list_to_convert) -> str:
        converted_string = ""
        if list_to_convert:
            for entry in list_to_convert:
                converted_string += f"- {entry}<br>"
            return converted_string[:-4]
        else:
            return ""
    
    def retrieve_status(self, task_ids: list = []) -> dict:
        """List status of all code scanning tasks in your account (-s for search by task id)"""
        result_status = {}
        if task_ids:
            length = len(task_ids)
            for i in range(0, length, 20):
                api_response = self.supabase_client.table('tasks').select("task_id, filepath, created_at, status").in_('task_id', task_ids[i:i+20]).execute() 
                for entry in api_response.data:
                    result_status.update({entry.get('task_id'): entry})
        else:
            api_response = self.supabase_client.table('tasks').select("task_id, filepath, created_at, status").execute()
            for entry in api_response.data:
                result_status.update({entry.get('task_id'): entry})

        if not result_status:
            print("No existing tasks to pull status for.")
        return result_status
    
    def wait_for_task_completion(self, task_ids: list = [], max_time: int = 30) -> None:
        """Wait for tasks to complete."""
        waiting_tasks = task_ids.copy()
        time_elapsed = 0
        while waiting_tasks and time_elapsed <= max_time:
            tasks_length = len(waiting_tasks)
            time.sleep(5)
            time_elapsed += 5
            tasks_status = self.retrieve_status(waiting_tasks)
            for key, value in tasks_status.items():
                status = value.get('status')
                if status == 'COMPLETE':
                    print(f"Task {key} completed.  Waiting on {tasks_length} tasks to complete.")
                    waiting_tasks.remove(key)
        if waiting_tasks:
            raise Exception("Tasks did not complete in time.")    

    def delete_tasks(self, task_ids) -> None:
        # print(f'Deleting tasks: {task_ids}')
        """Delete as task from the database by task id"""
        result = self.supabase_client.table('tasks').delete().in_('task_id', task_ids).execute()
        # TODO: Add summary and error checks
        # print(result)

    def sign_out(self) -> None:
        """Sign out of the server."""
        self.supabase_client.auth.sign_out()
        # print("Successfully signed out of server.")