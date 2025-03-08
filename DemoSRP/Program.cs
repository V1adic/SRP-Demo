using SRP;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});
builder.Services.AddSingleton<UserDatabase>();

var app = builder.Build();

app.UseSession();
app.UseStaticFiles();
app.UseRouting();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
    endpoints.MapGet("/register", async context =>
    {
        context.Response.ContentType = "text/html";
        await context.Response.SendFileAsync("wwwroot/register.html");
    });
    endpoints.MapGet("/login", async context =>
    {
        context.Response.ContentType = "text/html";
        await context.Response.SendFileAsync("wwwroot/login.html");
    });
    endpoints.MapGet("/", async context =>
    {
        context.Response.Redirect("/register"); // ѕо умолчанию открываем регистрацию
        await Task.CompletedTask;
    });
});

app.Run();