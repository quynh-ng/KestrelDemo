using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;

namespace KestrelDemo
{
	public class WebRequest
	{
		readonly RequestDelegate _next;
		readonly ILogger _logger;

		public WebRequest(RequestDelegate next, ILoggerFactory loggerFactory)
		{
			this._next = next;
			this._logger = loggerFactory.CreateLogger<WebRequest>();
		}

		public async Task InvokeAsync(HttpContext context)
		{
			// by-pass request of WebSocket
			if (context.WebSockets.IsWebSocketRequest)
			{
				await this.NextAsync(context).ConfigureAwait(false);
				return;
			}

			// OPTIONS request
			if (context.Request.Method.IsEquals("OPTIONS"))
			{
				context.Response.Headers.Add("Access-Control-Allow-Origin", "*");
				context.Response.Headers.Add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE");
				if (context.Request.Headers.ContainsKey("Access-Control-Request-Headers"))
					context.Response.Headers.Add("Access-Control-Request-Headers", context.Request.Headers["Access-Control-Request-Headers"]);
				return;
			}

			// process REST APIs request
			var requestUri = context.GetRequestUri();

			// prepare
			var correlationID = UtilityService.NewUUID;
			context.Items["PipelineStopwatch"] = Stopwatch.StartNew();

			var executionFilePath = requestUri.PathAndQuery;
			if (executionFilePath.IndexOf("?") > 0)
				executionFilePath = executionFilePath.Left(executionFilePath.IndexOf("?"));
			if (executionFilePath.Equals("~/") || executionFilePath.Equals("/"))
				executionFilePath = "";
			var executionFilePaths = string.IsNullOrWhiteSpace(executionFilePath)
				? new[] { "" }
				: executionFilePath.ToLower().ToArray('/', true);

			// request of favicon.ico file
			if (executionFilePaths[0].IsEquals("favicon.ico"))
			{
				context.ShowHttpError((int)HttpStatusCode.NotFound, "Not Found", "FileNotFoundException", correlationID);
				return;
			}

			if (this._logger.IsEnabled(LogLevel.Debug))
				this._logger.LogDebug($"Begin request: {context.Request.Method} {requestUri.PathAndQuery}");

			// TO DO: hidden segments, by-pass segments, static segments, ...

			// prepare query string
			var query = requestUri.ParseQuery(q =>
			{
				q["service-name"] = !string.IsNullOrWhiteSpace(executionFilePaths[0]) ? executionFilePaths[0].GetANSIUri() : "";
				q["object-name"] = executionFilePaths.Length > 1 && !string.IsNullOrWhiteSpace(executionFilePaths[1]) ? executionFilePaths[1].GetANSIUri() : "";
				q["object-identity"] = executionFilePaths.Length > 2 && !string.IsNullOrWhiteSpace(executionFilePaths[2]) ? executionFilePaths[2].GetANSIUri() : "";
			});

			// authentication
			if ("signin".IsEquals(query["service-name"]))
				await this.SignInAsync(context).ConfigureAwait(false);
			else if ("signout".IsEquals(query["service-name"]))
				await this.SignOutAsync(context).ConfigureAwait(false);

			var userIdentity = context.User.Identity;
			var userName = userIdentity != null && userIdentity.IsAuthenticated
				? userIdentity.Name
				: "Anonymous";

			// response
			var json = new JObject
			{
				{ "Verb", context.Request.Method },
				{ "Request", new JObject()
					{
						{ "AbsoluteUri", $"{requestUri}" },
						{ "RelativeUri", requestUri.PathAndQuery },
						{ "Query", string.Join("&", query.Select(kvp => kvp.Key + "=" + kvp.Value.UrlEncode())) }
					}
				},
				{ "User", userName }
			};

			// response
			//var contentEncoding = "deflate";
			//var bytes = json.ToString(Formatting.Indented).ToBytes().Compress(contentEncoding).ToArraySegment();
			//context.Response.Headers.Add("Content-Encoding", contentEncoding);
			//await context.WriteAsync(bytes).ConfigureAwait(false);

			//await context.WriteAsync(json, Formatting.Indented, correlationID).ConfigureAwait(false);

			var jarr = new JArray();
			for (var index = 0; index < 100; index++)
				jarr.Add(json.Clone());
			await context.WriteAsync(jarr, Formatting.Indented, correlationID).ConfigureAwait(false);

			// invoke next middleware
			await this.NextAsync(context).ConfigureAwait(false);
		}

		async Task SignInAsync(HttpContext context)
		{
			var userIdentity = new UserIdentity(UtilityService.NewUUID, "Tyrion Q. Nguyen", UtilityService.NewUUID, CookieAuthenticationDefaults.AuthenticationScheme)
			{
				Roles = new List<string> { "SystemAdministrator" },
				Privileges = new List<Privilege>
				{
					new Privilege
					{
						ServiceName = "books",
						ObjectName = "",
						ObjectIdentity = "",
						Role = PrivilegeRole.Administrator.ToString(),
						Actions = new List<string>() { "Full" }
					}
				}
			};

			var userPrincipal = new UserPrincipal(userIdentity);

			await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, userPrincipal, new AuthenticationProperties { IsPersistent = false });
			context.User = userPrincipal;
		}

		async Task SignOutAsync(HttpContext context)
		{
			await context.SignOutAsync().ConfigureAwait(false);
			context.User = new UserPrincipal();
		}

		async Task NextAsync(HttpContext context)
		{
			try
			{
				await this._next.Invoke(context).ConfigureAwait(false);
			}
			catch (InvalidOperationException) { }
			catch (Exception ex)
			{
				this._logger.Log(LogLevel.Debug, LogLevel.Error, $"Error occurred while invoking the next middleware: {ex.Message}", ex);
			}
		}
	}

}