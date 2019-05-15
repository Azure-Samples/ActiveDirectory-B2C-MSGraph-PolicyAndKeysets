# Programmatic access to Custom Policies and Keysets
[!NOTE] Custom Policies programmatic access is in public preview

[!NOTE] Keysets programmatic access is in private preview. To get access for trying out this feature, please send a email to aadb2cpreview@microsoft.com with your tenant name that you want enabled.


Programmatically access [Custom Policies](https://docs.microsoft.com/en-us/graph/api/resources/trustframeworkpolicy?view=graph-rest-beta) and [Keysets](https://github.com/Azure-Samples/ActiveDirectory-B2C-MSGraph-PolicyAndKeysets/blob/master/Keyset-API-Documentation.md) is in Private Preview. 

This is a sample command line tool that demonstrates managing custom trust framework policies (custom policy for short) and Policy keys in an Azure AD B2C tenant.  [Custom policy](https://docs.microsoft.com/en-us/azure/active-directory-b2c/active-directory-b2c-overview-custom) allows you to customize every aspect of the authentication flow. Azure AD B2C uses [Policy keys](https://docs.microsoft.com/en-us/azure/active-directory-b2c/active-directory-b2c-get-started-custom#create-the-encryption-key) to manage your secrets.

## Features

This project framework provides the following features:

* Create, Read, Update and Delete of TrustFramework Policies
* Create, Read, Update and Delete of KeySets
* Upload Secret, Certificate and Pkcs12 of Keysets
* Get Backed up Keysets
* Generate Key of Keysets
* Get Active Key in a Keyset

## Getting Started

### Prerequisites
This sample requires the following:

* [Visual Studio](https://www.visualstudio.com/en-us/downloads)
* [Azure AD B2C tenant](https://docs.microsoft.com/en-us/azure/active-directory-b2c/active-directory-b2c-get-started)

**NOTE: This API only accepts user tokens, and not application tokens. See more information below about Delegated Permissions.**

### Installation

#### Create global administrator

* An global administrator account is required to run admin-level operations and to consent to application permissions.  (for example: admin@myb2ctenant.onmicrosoft.com)

#### Register the delegated permissions application

1. Sign in to the [Application Registration Portal](https://apps.dev.microsoft.com/) using your Microsoft account.
2. Select **Add an app**, and enter a friendly name for the application (such as **Console App for Microsoft Graph (Delegated perms)**). Click **Create**.
3. On the application registration page, select **Add Platform**. Select the **Native App** tile and save your change. The **delegated permissions** operations in this sample use permissions that are specified in the AuthenticationHelper.cs file. This is why you don't need to assign any permissions to the app on this page.
4. Open the project PolicyAndKeys-Client and then update App.Config file in Visual Studio with the following. 
5. Make the **Application Id** value for this app the value of the **ida:ClientId** string.
6. Update **ida:Tenant** with the name of your tenant.  (for example: myb2ctenantname.onmicrosoft.com)

#### Build and run the sample

1. Open the sample solution in Visual Studio.
2. There are 2 projects - PolicyAndKeys-Client and PolicyAndKeys-Lib. 
3. In the PolicyAndKeys-Client project, Make sure to Replace the tenant name and ClientId in app.config by following [Register the delegated permissions application](#register-the-delegated-permissions-application)
4. Build the sample.
5. Using cmd or PowerShell, navigate to <Path to sample code>/bin/Debug. Run the client executable **PolicyAndKeys-Client.exe**.
6. Sign in as a global administrator.  (for example: admin@myb2ctenant.onmicrosoft.com)
7. The output will show the results of calling the Graph API for trustFrameworkPolices.

## Questions and comments

Questions about this sample should be posted to [Stack Overflow](https://stackoverflow.com/questions/tagged/azure-ad-b2c). Make sure that your questions or comments are tagged with [azure-ad-b2c].

## Contributing

If you'd like to contribute to this sample, see [CONTRIBUTING.MD](/CONTRIBUTING.md).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.## Resources

## Resources
- [Custom Policies](https://docs.microsoft.com/en-us/graph/api/resources/trustframeworkpolicy?view=graph-rest-beta)

The sample uses the Microsoft Authentication Library (MSAL) for authentication. The sample demonstrates both delegated admin permissions.  (app only permissions are not supported yet)

**Delegated permissions** are used by apps that have a signed-in user present (in this case tenant administrator). For these apps either the user or an administrator consents to the permissions that the app requests and the app is delegated permission to act as the signed-in user when making calls to Microsoft Graph. Some delegated permissions can be consented to by non-administrative users, but some higher-privileged permissions require administrator consent.

See [Delegated permissions, Application permissions, and effective permissions](https://developer.microsoft.com/en-us/graph/docs/concepts/permissions_reference#delegated-permissions-application-permissions-and-effective-permissions) for more information about these permission types.
