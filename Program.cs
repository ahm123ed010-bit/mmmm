using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Moarekh.Data;
using Moarekh.Services;

// تحميل ملف .env (لو موجود) عشان التشغيل على جهازك يبقى أسهل: DATABASE_URL و ADMIN_PASSWORD
foreach (var envFile in new[] { Path.Combine(Directory.GetCurrentDirectory(), ".env"), Path.Combine(AppContext.BaseDirectory, ".env") })
{
    if (!File.Exists(envFile)) continue;
    foreach (var line in File.ReadAllLines(envFile))
    {
        var t = line.Trim();
        if (t.Length == 0 || t.StartsWith('#')) continue;
        var i = t.IndexOf('=');
        if (i <= 0) continue;
        var k = t[..i].Trim();
        var v = t[(i + 1)..].Trim().Trim('"');
        if (Environment.GetEnvironmentVariable(k) == null) Environment.SetEnvironmentVariable(k, v);
    }
}

var builder = WebApplication.CreateBuilder(args);

var port = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrEmpty(port)) builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

var rawDb = builder.Configuration["DATABASE_URL"] ?? builder.Configuration.GetConnectionString("Default");
if (string.IsNullOrWhiteSpace(rawDb))
    throw new InvalidOperationException("حط DATABASE_URL (رابط PostgreSQL) في المتغيّرات أو في ملف .env");

builder.Services.AddDbContext<AppDb>(o => o.UseNpgsql(DbUrl.ToNpgsql(rawDb)));
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<Localizer>();
builder.Services.AddScoped<Notifier>();
builder.Services.AddScoped<DisciplineService>();
builder.Services.AddScoped<GroupAccess>();
builder.Services.AddSingleton<RateLimiter>();
builder.Services.AddSingleton<FileStore>();

builder.Services.AddControllersWithViews(o => o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));
builder.Services.AddAntiforgery(o => { o.HeaderName = "RequestVerificationToken"; o.Cookie.Name = "moarekh.af"; });

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o =>
{
    o.Cookie.Name = "moarekh.auth";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Lax;
    o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    o.ExpireTimeSpan = TimeSpan.FromDays(7);
    o.LoginPath = "/login";
    o.AccessDeniedPath = "/denied";
    o.Events.OnRedirectToLogin = ctx =>
    {
        if (ctx.Request.Path.StartsWithSegments("/api") || ctx.Request.Headers.XRequestedWith == "XMLHttpRequest")
            ctx.Response.StatusCode = 401;
        else ctx.Response.Redirect(ctx.RedirectUri);
        return Task.CompletedTask;
    };
    // الجلسة لازم تكون موجودة والحساب نشط: ده بيخلّي تعطيل الحساب أو الفصل يطلّع الطالب فورًا
    o.Events.OnValidatePrincipal = async ctx =>
    {
        if (!Guid.TryParse(ctx.Principal?.FindFirstValue("sid"), out var sid))
        {
            ctx.RejectPrincipal(); await ctx.HttpContext.SignOutAsync(); return;
        }
        var db = ctx.HttpContext.RequestServices.GetRequiredService<AppDb>();
        var now = DateTime.UtcNow;
        var ok = await db.AuthSessions.AnyAsync(s => s.Id == sid && s.ExpiresAt > now && s.User.IsActive);
        if (!ok) { ctx.RejectPrincipal(); await ctx.HttpContext.SignOutAsync(); }
    };
});
builder.Services.AddAuthorization();

// رفع الفيديوهات الكبيرة
builder.Services.Configure<FormOptions>(o => o.MultipartBodyLengthLimit = 2_147_483_648);
builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = 2_147_483_648);

// خلف بروكسي (Render / Railway / Nginx)
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownNetworks.Clear();
    o.KnownProxies.Clear();
});

var app = builder.Build();

// ---------- إنشاء الجداول + حسابات الأدمن (شريف & أحمد عبد الله) ----------
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    var log = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    await db.Database.EnsureCreatedAsync();
    if (!await db.DisciplineRules.AnyAsync()) db.DisciplineRules.Add(new DisciplineRule { Id = 1 });

    // إنشاء حسابات الأدمن لو مش موجودة بس. مفيش إعادة ضبط للباسورد عند كل تشغيل.
    var adminPw = Environment.GetEnvironmentVariable("ADMIN_PASSWORD");
    var needSherif = !await db.Users.AnyAsync(u => u.Username == "sherif");
    var needAhmed = !await db.Users.AnyAsync(u => u.Username == "ahmed");
    if (needSherif || needAhmed)
    {
        if (string.IsNullOrWhiteSpace(adminPw) || adminPw.Length < 8)
            throw new InvalidOperationException("حط ADMIN_PASSWORD (8 حروف على الأقل) عشان يتعمل حساب الأدمن أول مرة");
        var hash = Passwords.Hash(adminPw);
        if (needSherif)
        {
            db.Users.Add(new User { Username = "sherif", PasswordHash = hash, Role = Role.Admin, FullName = "مستر شريف", IsActive = true });
            log.LogInformation("تم إنشاء حساب الأدمن: sherif");
        }
        if (needAhmed)
        {
            db.Users.Add(new User { Username = "ahmed", PasswordHash = hash, Role = Role.Admin, FullName = "أحمد عبد الله", IsActive = true });
            log.LogInformation("تم إنشاء حساب الأدمن: ahmed");
        }
    }

    await db.SaveChangesAsync();
}

app.UseForwardedHeaders();
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        if (ctx.File.Name == "sw.js") ctx.Context.Response.Headers.CacheControl = "no-cache";
    }
});
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
