using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Build.Execution;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using PriceTrackrAPI.Data;
using PriceTrackrAPI.Services;
using PriceTrackrAPI.Services.Contract;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add DbContext
builder.Services.AddDbContext<AppDbContext>(option =>
    option.UseNpgsql(builder.Configuration.GetConnectionString("Development")));

//// Add FluentEmail services
//builder.Services
//    .AddFluentEmail(builder.Configuration["Email:SenderEmail"], builder.Configuration["Email:Sender"])
//    .AddSmtpSender(builder.Configuration["Email:Host"], builder.Configuration.GetValue<int>("Email:Port"));

// Add Identity services
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = true;
    options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
})
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

// Configure custom token provider settings if needed
builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    // Set custom expiration 
    options.TokenLifespan = TimeSpan.FromHours(24);
});


// Add Session
//builder.Services.AddDistributedMemoryCache();
//builder.Services.AddSession(options =>
//{
//    options.IdleTimeout = TimeSpan.FromMinutes(30);
//    options.Cookie.HttpOnly = true;
//    options.Cookie.IsEssential = true;
//    options.Cookie.SameSite = SameSiteMode.Strict;
//    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Requires HTTPS 
//});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
            // Can add validAudience and validIssuer after implement Angular frontend
        };


        // Extract JWT from cookies instead of Authorization Header
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                context.Token = context.Request.Cookies["X-Access-Token"];
                return Task.CompletedTask;
            }
        };

        // Custom event handler to check token blacklist
        //options.Events = new JwtBearerEvents
        //{
        //    OnTokenValidated = async context =>
        //    {
        //        //var distributedCache = context.HttpContext.RequestServices.GetRequiredService<IDistributedCache>();
        //        var tokenString = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

        //        // Check if token is blacklisted
        //        var blacklisted = await distributedCache.GetStringAsync($"blacklisted_token:{tokenString}");
        //        if (blacklisted != null)
        //        {
        //            context.Fail("Token has been revoked");
        //        }
        //    }
        //};
    });

// Add Cookie Policy


builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminPolicy", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserPolicy", policy => policy.RequireRole("User"));
});

// Register the HttpContextAccessor
builder.Services.AddHttpContextAccessor();

// Add auth service
builder.Services.AddScoped<IAuthService, AuthService>();

// Add Email services
builder.Services.AddScoped<IEmailService, EmailService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();

    app.UseCors(options =>
    {
        options.WithOrigins("http://localhost:4200")
        .AllowAnyMethod()
        .AllowAnyHeader()
        .AllowCredentials();
    });

    var application = app.Services.CreateScope().ServiceProvider.GetRequiredService<AppDbContext>();

    var pendingMigrations = await application.Database.GetPendingMigrationsAsync();
    if (pendingMigrations != null)
        await application.Database.MigrateAsync();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
