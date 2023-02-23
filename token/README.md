## Impersonate

A simple library that allows you to steal/make/impersonate tokens of a process and set/get token privileges.

## How token make/steal/impersonate token works

### Steal Token

The `steal_token()` function attempts to retrieve a duplicated access token associated with a process, given its process ID. If successful, it returns a handle to the duplicated token, otherwise it returns an error indicating the reason for failure.

* Calls the `OpenProcess` function to retrieve a handle to an existing local process.
* Calls the `OpenProcessToken` function to retrieve a handle to the access token associated with the process.
* Calls the `DuplicateTokenEx` function to create a new access token that duplicates the original one.
* If all calls are successful, it returns the handle to the duplicated token.

### Make Token

The `make_token()` function attempts to authenticate a user with a given `domain`, `username`, and `password` by calling the `LogonUserW` function. If successful, it returns a handle to a token that represents the logged-on user, which can be used to impersonate the specified user or create a process that runs in the context of the specified user.

* Calls the `LogonUserW` to log the user onto the local computer. If the logon is successful, the function returns the token handle.

### Impersonate Token

This `impersonate_token` function allows the calling thread to impersonate the security context of a logged-on user, represented by a token handle. This can be useful for performing actions on behalf of another user, such as accessing files or resources that are only available to that user.

* Calls the `ImpersonateLoggedOnUser` function which allows the calling thread to temporarily take on the security context of the logged-on user. If the function call is successful, it returns the token handle

### Set Token Privileges

The `set_token_privileges` function takes a privilege name and a boolean value to either enable or disable that privilege in the current process's access token. It first looks up the locally unique identifier (`LUID`) for the specified privilege name using the `LookupPrivilegeValueW` function. Then, it constructs a `TOKEN_PRIVILEGES` structure with the `LUID` and the desired attributes (enabled or disabled). The function then opens the process's access token using the `OpenProcessToken` function and calls the `AdjustTokenPrivileges` function to adjust the privileges in the token.

* Calls the `LookupPrivilegeValueW` function to look up the locally unique identifier (`LUID`) for the specified privilege name
* Constructs a `TOKEN_PRIVILEGES` structure with the `LUID`
* Calls `OpenProcessToken` to opens the process's access token
* Calls the `AdjustTokenPrivileges` function to adjust the privileges in the token.

### Get Token Privileges (TODO)


### Named Pipe Token Impersonation (TODO)


## Credits / References

* [C5pider](https://twitter.com/C5pider): https://github.com/HavocFramework/Havoc
* [zblurx](https://twitter.com/_zblurx): https://github.com/zblurx/impersonate-rs (Just saw this was done too. This one is much better than mine and actually usable)
* This project was dedicated to [@_RastaMouse](https://twitter.com/_RastaMouse)