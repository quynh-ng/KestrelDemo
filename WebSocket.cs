using System;
using System.Linq;
using System.Threading.Tasks;
using System.Net.WebSockets;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using net.vieapps.Components.Utility;

namespace KestrelDemo
{
    public class WebSocket
    {
		readonly RequestDelegate _next;
		ILogger _logger;
		net.vieapps.Components.WebSockets.WebSocket _websocket = null;

		public WebSocket(RequestDelegate next, ILoggerFactory loggerFactory)
		{
			this._next = next;
			this._logger = loggerFactory.CreateLogger<WebSocket>();
			this._websocket = new net.vieapps.Components.WebSockets.WebSocket(loggerFactory)
			{
				OnError = (websocket, exception) =>
				{
					this._logger.LogError(exception, $"Got an error: {websocket?.ID} @ {websocket?.RemoteEndPoint} => {exception.Message}");
				},
				OnConnectionEstablished = (websocket) =>
				{
					this._logger.LogDebug($"Connection is established: {websocket.ID} @ {websocket.RemoteEndPoint}");
					if (this._logger.IsEnabled(LogLevel.Debug))
						this._logger.LogDebug($"Total of WebSocket connections: {this._websocket.GetWebSockets().Count()}");
				},
				OnConnectionBroken = (websocket) =>
				{
					this._logger.LogDebug($"Connection is broken: {websocket.ID} @ {websocket.RemoteEndPoint}");
				},
				OnMessageReceived = (websocket, result, data) =>
				{
					var message = result.MessageType == WebSocketMessageType.Text ? data.GetString() : "(binary message)";
					if (!message.IsStartsWith("Stress Test Message"))
						this._logger.LogDebug($"Got a message: {websocket.ID} @ {websocket.RemoteEndPoint} => {message}");
					if (message.IsEndsWith("pingback"))
						websocket.SendAsync($"Ping back message => {websocket.ID} @ {websocket.RemoteEndPoint} / {websocket.LocalEndPoint} [{message}]", true);
				}
			};
			this._logger.LogDebug($"WebSocket is started");
		}

		~WebSocket()
		{
			this._websocket.Dispose();
		}

		public async Task InvokeAsync(HttpContext context)
		{
			await this._websocket.WrapAsync(context, async (ctx) =>
			{
				try
				{
					await this._next.Invoke(ctx).ConfigureAwait(false);
				}
				catch (InvalidOperationException) { }
				catch (Exception ex)
				{
					this._logger.Log(LogLevel.Debug, LogLevel.Error, $"Error occurred while invoking the next middleware: {ex.Message}", ex);
				}
			}).ConfigureAwait(false);
		}
	}
}
