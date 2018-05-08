#define Default // or Limits

using System;
using System.IO;
using System.Diagnostics;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Caching.Distributed;

using net.vieapps.Components.Utility;

namespace KestrelDemo
{
	public class Startup
	{
		public IConfiguration Configuration { get; }

		public Startup(IConfiguration configuration)
		{
			this.Configuration = configuration;
		}

#if Default

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			services.AddResponseCompression(options => options.EnableForHttps = true);
			services.AddLogging(builder => builder.SetMinimumLevel(this.Configuration.GetAppJsonSetting("Logging/LogLevel/Default", "Warning").ToEnum<LogLevel>()));
			services.AddCache(options => this.Configuration.GetSection("Cache").Bind(options));
			services.AddSession(options =>
			{
				options.IdleTimeout = TimeSpan.FromMinutes(30);
				options.Cookie.Name = "VIEApps-Session";
				options.Cookie.HttpOnly = true;
			});
			services.AddAuthentication(options => options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme)
				.AddCookie(options =>
				{
					options.Cookie.Name = "VIEApps-Auth";
					options.Cookie.HttpOnly = true;
					options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
					options.SlidingExpiration = true;
				});
			services.AddDataProtection()
				.SetDefaultKeyLifetime(TimeSpan.FromDays(7))
				.SetApplicationName("VIEApps-NGX")
				.UseCryptographicAlgorithms(new AuthenticatedEncryptorConfiguration
				{
					EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
					ValidationAlgorithm = ValidationAlgorithm.HMACSHA256
				});
			services.Configure<IISOptions>(options =>
			{
				options.ForwardClientCertificate = false;
				options.AutomaticAuthentication = true;
			});
		}

		public void Configure(IApplicationBuilder app)
		{
			var loggerFactory = app.ApplicationServices.GetService<ILoggerFactory>();
			Logger.AssignLoggerFactory(loggerFactory);

			var path = this.Configuration.GetAppJsonSetting("Logging/Path");
			if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
			{
				path += Path.DirectorySeparatorChar.ToString() + "{Date}_Test-Kestrel.txt";
				loggerFactory.AddFile(path, this.Configuration.GetAppJsonSetting("Logging/LogLevel/Default", "Warning").ToEnum<LogLevel>());
				Logger.Log<Startup>(LogLevel.Information, LogLevel.Information, $"Rolling log files is enabled => {path}");
			}

			app.UseErrorCodePages();
			app.UseResponseCompression();
			app.UseCache();
			app.UseSession();
			app.UseAuthentication();
			app.UseWebSockets(new WebSocketOptions { ReceiveBufferSize = net.vieapps.Components.WebSockets.WebSocket.ReceiveBufferSize });
			app.UseMiddleware<WebSocket>();
			app.UseMiddleware<WebRequest>();
		}
#elif Limits
        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            var serverAddressesFeature = app.ServerFeatures.Get<IServerAddressesFeature>();

            app.UseStaticFiles();

		#region snippet_Limits
            app.Run(async (context) =>
            {
                context.Features.Get<IHttpMaxRequestBodySizeFeature>()
                    .MaxRequestBodySize = 10 * 1024;
                context.Features.Get<IHttpMinRequestBodyDataRateFeature>()
                    .MinDataRate = new MinDataRate(bytesPerSecond: 100, gracePeriod: TimeSpan.FromSeconds(10));
                context.Features.Get<IHttpMinResponseDataRateFeature>()
                    .MinDataRate = new MinDataRate(bytesPerSecond: 100, gracePeriod: TimeSpan.FromSeconds(10));
		#endregion
                context.Response.ContentType = "text/html";
                await context.Response
                    .WriteAsync("<p>Hosted by Kestrel</p>");

                if (serverAddressesFeature != null)
                {
                    await context.Response
                        .WriteAsync("<p>Listening on the following addresses: " +
                            string.Join(", ", serverAddressesFeature.Addresses) +
                            "</p>");
                }

                await context.Response.WriteAsync($"<p>Request URL: {context.Request.GetDisplayUrl()}<p>");
            });
        }
#endif
	}
}