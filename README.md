CLEAN ARCHITECTURE IN SERVERLESS AZURE FUNCTION
yusuf sarıkaya

The Create Clean Architecture project is complex and requires additional experience. You may lose control of your project as it grows. When my best friend Mücahit Furkan Ardogan and I were working on a large project in Turkey, we encountered numerous challenges, such as continuing to build all domains of the project utilizing micro-services and keeping consistency of coding approach and data with each other for these services.

we have decided to use clean architecture in our project and reduce mismatches in the language of domain models between us and domain experts. Eric Evans uses the ubiquitous language term, which helps you and domain experts remove ambiguity during development. This clarification assisted us in eliminating some misunderstanding during development. But we thought we needed something more.

Based on our experience, we have adopted several language best practices like as name conventions, keeping your class short and with as few lines of code as possible, and sperating concern across the class. Yes, these steps aided us, but it was not what we expected.

We employed various excellent tactics that are commonly used around the world, and I’d like to explain these methods as much as possible in Azure Function. I believe these procedures will assist you in developing a clean architecture in Azure.

Created Azure Function Project In An Isolated Worker
When Azure Function was released by Microsoft, they used in-process mode, which has a tight coupling between the host process and the.NET function. By isolating the Azure function, you can use all.net versions with the Azure function, even if a version of.net was not released for the Azure function.

Another significant advantage of Azure's Isolated worker function is You will have a program.cs when you create an isolated function app. This program class will let you use middleware, save your services in containers to use as dependency injection, and make many configurations for your project. Before the isolated version, you had to create the startup class manually.

Here is a default program class. We will see its usage in the next section of this article.


2. Use domain-driven design to plan your functions, applications, domains, and infrastructure operations

Based on domain-driven design, you have to define your entities’ class in domain layer, and all layers should depend on this layer, but this layer shouldn't reference other class libraries.

Another important part of your domain-driven design in C# is that you should code first to build your database object. Because it should be created with domain experts and other participants. And also, the code-first approach is so useful when you want to easily start up and change database objects and columns. It is also more testable, and database class entities can involve some behavior of the class rather than only using the class column and saving data.


Example view of DDD(Domain-Driven Design)
Here is an example of a class library and function visibility in the Azure function clean architecture. You can take a look at the screenshot of Solution Explorer and observe that it involves one entity, which is called “User”. You can aggregate your entity class in the aggregation folder of the domain layer.

Another important thing is that you should keep your database service interface in the domain layer because applications and infrastructure libraries will consume it from here.


3. Validate your DTO (Data Transfer Object) when you receive data from the user.

You shouldn’t open your entities directly to your clients. Your client should talk with your functions via a data transfer object. By the way, you can create your DTO for each function and make specific input parameters. But here is one important thing: when you get data from your client, you should check whether the data is correct or not. Here is one example: We have created one UserDto object to take data from the client to create and update users.


When you observe our UserDto class, you will see we have defined some properties for the user to use in binding data from the client. Now, how can we check if this data is correct or not?

One traditional way is to check the function manually. That is so old and makes your code as dirty as possible. Another way is to create a guard class and validate your data. But for now, I will suggest commonly used third-party packages for this operation. This package is FluentValidation. You can use this package to validate your DTO classes at the application layer. I highly recommend configuring and using this package in the application layer.

Here are two steps: one is configuring your validation in your assembly, and the other is regarding how we can create the Validator object of userDto.

You should register for fluent validation in your class via the service collection program.cs

```c#
services.AddValidatorsFromAssembly(typeof(Assembly).Assembly);
using FluentValidation;

namespace CleanFunctionApp.Application.UseCases.Users.DTO;

public class UserDtoValidation : AbstractValidator<UserDto>
{
    public UserDtoValidation()
    {
        RuleFor(x=>x.Email).NotEmpty().EmailAddress();
        RuleFor(x => x.Name).NotEmpty().MinimumLength(2);
        RuleFor(x => x.Password).NotEmpty().MinimumLength(8);
        RuleFor(x => x.Role).NotEmpty().MinimumLength(2);
    }
}
```

You can see AbstractValidator uses the AbstractValidator generic class to access its validation method. When you use the RuleFor method, you will access other fluent methods of validation.

4. Send requests to the application layer from the function layer via mediatR

In a clean architecture, you should avoid tight coupling approaches, like one class shouldn’t know another class directly and speak over the interface or work based on the request-handle-response process. MediatR will help you send your request from the API/function layer and help you handle it on the application later. By the way, both don’t know each other directly and speak over the request object in MediatR.

We have used MediatR a little bit differently in our project. We have created a base class to help with all functions and send requests to the application layer. You can take a look at the following classes and try to discover our abstract class and one implementation of its

```c#
using System.Net;
using MediatR;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace CleanFunctionApp.Function;

public abstract class Abstraction<T>
{
    private readonly IMediator mediator;

    public Abstraction(IMediator mediator)
    {
        this.mediator = mediator;
    }
    
    protected async Task<HttpResponseData> PostResponse(HttpRequestData req, IRequest request)
    {
        var response = req.CreateResponse(HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "application/json; charset=utf-8");
        await mediator.Send(request);
        return response;
    }
    
    protected async Task<HttpResponseData> PostResponse<TResponse>(HttpRequestData req, IRequest<TResponse> request)
    {
        var response = req.CreateResponse(HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "application/json; charset=utf-8");
        TResponse result =  await mediator.Send(request);
        await  response.WriteStringAsync(JsonConvert.SerializeObject(result));
        return response;
    }
}
```

```c#
using System.Net;
using CleanFunctionApp.Application.UseCases.Users;
using CleanFunctionApp.Application.UseCases.Users.DTO;
using MediatR;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

namespace CleanFunctionApp.Function.User;

public class InsertUserFunction: Abstraction<InsertUserFunction>
{

    public InsertUserFunction(IMediator mediator):base(mediator)
    {
    }
    
    [Function("InsertUser")]
    public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequestData req) =>
        await PostResponse(
            req,new InsertUserCommand(req.Convert<UserDto>())
            );
}
```

You see in the preceding abstract class, we have initialized one IMediator interface and send request to the handler in application layer. Now we can see the example of handler.

```c#
using AutoMapper;
using CleanFunctionApp.Application.UseCases.Users.DTO;
using CleanFunctionApp.Domain.Abstract;
using CleanFunctionApp.Domain.Aggregation.Users;
using MediatR;

namespace CleanFunctionApp.Application.UseCases.Users;

public record InsertUserCommand(UserDto Model) : IRequest;

public class InsertUserHandler : Handler, IRequestHandler<InsertUserCommand>
{
    private readonly IUnitOfWork unitOfWork;
    private readonly IMapper mapper;
    private readonly IPasswordHashService passwordHashService;

    public InsertUserHandler(IUnitOfWork unitOfWork, IMapper mapper, IPasswordHashService passwordHashService)
    {
        this.unitOfWork = unitOfWork;
        this.mapper = mapper;
        this.passwordHashService = passwordHashService;
    }

    public async Task Handle(InsertUserCommand request, CancellationToken cancellationToken)
    {
        var userRepository = unitOfWork.UserRepository();
        var user = mapper.Map<User>(request.Model);
        user.Password = passwordHashService.ComputeSha256Hash(user.Password);
        userRepository.Insert(user);
        await unitOfWork.CommitAsync(cancellationToken);
    }
}
```

Now you saw the example of the request and handler of MediatR. That is the one crucial process of clean architecture.

5. Global Exception Handler Via Using Middleware

Middleware is a piece of code that sits between your client request and your code’s response. Via the middleware, you can take lots of action, like managing your exception, authorization, logging, etc. I will explain how exception middleware manipulates all exceptions in your code. It gives you the principle of single responsibility. You will define it once, and if you need to change it in the future, you only need to touch this piece of code.

You will see an example of exception middleware below, which is implemented in the IFunctionsWorkerMiddleware interface. In the try scope, we will execute the current function, and if it throws an error, we will return it in the catch scope.

```c#
using System.Net;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Azure.Functions.Worker.Middleware;

namespace CleanFunctionApp.Function.Middlewares;

public class ExceptionLoggingMiddleware : IFunctionsWorkerMiddleware
{
    public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
    {
        try
        {
            await next(context);
        }
        catch (Exception ex)
        {
            List<string> trace = new();
            Exception? tracer = ex;
            while (tracer is not null)
            {
                    trace.Add(tracer!.Message);
                    tracer = tracer!.InnerException;
            }
            
            // return this response with status code 500
            var httpReqData = await context.GetHttpRequestDataAsync();
            if (httpReqData != null)
            {
                var newHttpResponse = httpReqData.CreateResponse(HttpStatusCode.InternalServerError);
                await newHttpResponse.WriteAsJsonAsync(new
                    {
                        success = false,
                        errors = JsonSerializer.Serialize(trace.ToArray())
                    },
                    newHttpResponse.StatusCode);
                context.GetInvocationResult().Value = newHttpResponse;
            }
        }
    }
}
```

But you have to register your middleware in your program.cs, as we mentioned before in the isolated function segments.

```c#
var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults(x =>
    {
        x.UseMiddleware<ExceptionLoggingMiddleware>();
    }).Build();
    host.Run();
```

6. Authorization With Azure Function

Authentication and authorization are different in Azure functions. It has built-in authorization that you should integrate into your Azure portal with EasyAuth or different providers like Facebook, Google, Twitter, etc.

But in our architecture, we will use JWT authorization via middleware and the authorize attribute. This step can look more complicated than others because we should run it to integrate our database But I will demonstrate it for you to understand better.


Demonstration of basic token process
Process of JWT token:

a. Take a look at the database and check whatever user exist on Database.

b. Build token claims and return token to client if user exist

c. Throw exception if user not exist

You will see source code regarding of these three steps in bellow. We should give claims to the JWT service to generate tokens regarding this step.

```c#
using CleanFunctionApp.Application.Services;
using CleanFunctionApp.Domain.Abstract;
using MediatR;

namespace CleanFunctionApp.Application.UseCases.Users;

public record LoginUser(string Email, string Password) : IRequest<string>;

public class LoginUserHandler : Handler, IRequestHandler<LoginUser, string>
{
    private readonly IUnitOfWork unitOfWork;
    private readonly IJwtService jwtService;

    public LoginUserHandler(IUnitOfWork unitOfWork, IJwtService jwtService)
    {
        this.unitOfWork = unitOfWork;
        this.jwtService = jwtService;
    }

    public Task<string> Handle(LoginUser request, CancellationToken cancellationToken)
    {
        var userRepository = unitOfWork.UserRepository();
        var user = userRepository.GetByEmail(request.Email);
        if (user == null) throw new Exception("Invalid_Email");
        if (user.Password != request.Password) throw new Exception("Invalid_Password");

        var tokens = ClaimBuilder.Create()
            .SetEmail(user.Email)
            .SetRole(user.Role)
            .SetId(user.Id.ToString())
            .Build();

        var token = jwtService.BuildToken(tokens);

        return Success(token);
    }
}
```

```c#
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CleanFunctionApp.Domain.Abstract;
using Microsoft.IdentityModel.Tokens;

namespace CleanFunctionApp.Function.Services;

public class JwtService: IJwtService
{
   private readonly IJwtOption option;
   public JwtService(IJwtOption option)
   {
      this.option = option;
   }
   public string BuildToken(IEnumerable<Claim> claims)
   {
      SymmetricSecurityKey key = new(Encoding.ASCII.GetBytes(option.Secret));
      SigningCredentials credentials = new(key, SecurityAlgorithms.HmacSha256);
      
      JwtSecurityToken jwt = new(
         claims: claims,
         issuer: option.Issuer,
         expires:DateTime.Now.AddMinutes(option.Expires),
         audience: option.Audience,
         notBefore: DateTime.Now,
         signingCredentials: credentials
      );
      
      var token = new JwtSecurityTokenHandler().WriteToken(jwt);

      return token;
   }
}
```

Now, the generate token function code is implemented correctly. But how can we check users and roles when we get tokens via header? It is so simple that we should create an authorize attribute and use the over particular function method. The other step is to generate new middleware and validate roles.

```c#
namespace CleanFunctionApp.Function;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method | AttributeTargets.Parameter, AllowMultiple = true)]
public class AuthorizeAttribute : Attribute
{
    public string[] Roles { get; }

    public AuthorizeAttribute(params string[] roles)
    {
        Roles = roles;
    }
}
```

```c#
using System.Reflection;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;

namespace CleanFunctionApp.Function.Middlewares;

public class AuthorizationMiddleware : IFunctionsWorkerMiddleware
{
    private readonly IAuthorizationService service;
    public AuthorizationMiddleware(IAuthorizationService service)
    {
        this.service = service;
    }
    public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
    {
        // if that is swagger request, skip authorization
        if (context.FunctionDefinition.Name == "RenderSwaggerUI" || context.FunctionDefinition.Name == "RenderSwaggerDocument")
        {
            await next(context);
            return;
        }
        
        // Read request headers
        var headers = await context.GetHttpRequestDataAsync();
        var bearer = headers.Headers
            .FirstOrDefault(x => x.Key == "Authorization").Value;
        
        var targetMethod = GetTargetFunctionMethod(context);
        var attributes = targetMethod.GetCustomAttributes<AuthorizeAttribute>(true);

        if (attributes.Any() && bearer is null)
        {
            throw new UnauthorizedAccessException("Unauthorized");
        }

        if (bearer is not null && service.CheckAuthorization(bearer.FirstOrDefault()!, attributes.FirstOrDefault()?.Roles))
             await next(context);
        else
            throw new UnauthorizedAccessException("Unauthorized");
    }

    public static MethodInfo GetTargetFunctionMethod(FunctionContext context)
    {
        var entryPoint = context.FunctionDefinition.EntryPoint;
        var assemblyPath = context.FunctionDefinition.PathToAssembly;
        var assembly = Assembly.LoadFrom(assemblyPath);
        var typeName = entryPoint.Substring(0, entryPoint.LastIndexOf('.'));
        var type = assembly.GetType(typeName);
        var methodName = entryPoint.Substring(entryPoint.LastIndexOf('.') + 1);
        var method = type.GetMethod(methodName);
        return method;
    }
}
```

In the previous middleware, you will see we have implemented our code into the new middleware and implemented its roles and token validation code. In the middleware, we will check this particular function, which is fired by the user client, to see whether it has an authorize attribute or not. If it has an authorize attribute, we check which roles it has. By the way, we can compare it with the JWT token and function authentication requirements.

7. Add swagger to demonstrate your function, request and response

Swagger helps developers test their functions and observe requests and responses.

```c#
using System.Net;
using CleanFunctionApp.Application.UseCases.Users;
using CleanFunctionApp.Application.UseCases.Users.DTO;
using MediatR;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Azure.WebJobs.Extensions.OpenApi.Core.Attributes;
using Microsoft.Azure.WebJobs.Extensions.OpenApi.Core.Enums;
using Microsoft.Extensions.Logging;

namespace CleanFunctionApp.Function.User;

public class InsertUserFunction: Abstraction<InsertUserFunction>
{

    public InsertUserFunction(IMediator mediator):base(mediator)
    {
    }
    
    [Function("InsertUser")]
    [OpenApiOperation(operationId: "selectAllJpbs", tags: new[] { "User" }, Summary = "Insert New User.", Description = "Operation Insert new user to database.", Visibility = OpenApiVisibilityType.Important)]
    [OpenApiRequestBody(contentType: "application/json", bodyType: typeof(UserDto), Required = true, Description = "Add new user to database.")]
    [OpenApiResponseWithBody(statusCode: HttpStatusCode.OK, contentType: "application/json", bodyType: typeof(string), Summary = "Job list.", Description = "List of all the jobs.")]
    public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequestData req) =>
        await PostResponse(
            req,new InsertUserCommand(req.Convert<UserDto>())
            );
}
```

You will see in the preceding piece of code some attributes that help you define your swagger information.

8. Unit of Work Design Pattern

The Unit of Work design pattern is a software design pattern that is widely used in data-centric software development. You can group your database operations and use them in different operations. We have implemented a unit-of-work design pattern and used it in our project. In the following code, describe the basic operation of a unit of work. You should take care of two points here. One is that you should create these interfaces in the domain layer of your project to access them in the application layer. Because you know the domain layer is referenced in another class library of the project. Another is that transaction and commit operations should be in the domain layer and should be used in the application layer. Because the application handler will use and access different repositories, the management of saving data should be in this layer.

```c#
using CleanFunctionApp.Domain.Aggregation.Users;

namespace CleanFunctionApp.Domain.Abstract;

public interface IUnitOfWork
{
    ITransaction BeginTransaction();
    Task CommitAsync(CancellationToken cancellationToken);
    IUserRepository UserRepository();
}
```

```c#
using CleanFunctionApp.Domain.Abstract;
using CleanFunctionApp.Domain.Aggregation.Users;
using CleanFunctionApp.Infrastructure.Repositories;

namespace CleanFunctionApp.Infrastructure;

public class UnitOfWork : IUnitOfWork
{
    private readonly Context context;
    public UnitOfWork(Context context)
    {
        this.context = context;
    }
    
    public ITransaction BeginTransaction() => new Transaction(context);
    public Task CommitAsync(CancellationToken cancellationToken)
    {
        return context.SaveChangesAsync(cancellationToken);
    }

    private IUserRepository userRepository;
    public IUserRepository UserRepository() => userRepository = new UserRepository(context);
}
```

```c#
using CleanFunctionApp.Domain.Aggregation.Common;

namespace CleanFunctionApp.Domain.Aggregation.Users;

public interface IUserRepository
{
    User[] Search(Specification<User> specification,Pagination? pagination);
    void Insert(User user);
    User Get(int id);
    User GetByEmail(string email);
}
```

```c#
using CleanFunctionApp.Domain.Aggregation.Common;
using CleanFunctionApp.Domain.Aggregation.Users;

namespace CleanFunctionApp.Infrastructure.Repositories;
using Common;
public class UserRepository : Repository<User>, IUserRepository
{
    public UserRepository(Context context) : base(context)
    {
    }

    public User[] Search()
    {
        return entity.ToArray();
    }

    public User[] Search(Specification<User>? specification, Pagination? pagination)
    {
        return entity.Filter(specification).Paginate(pagination).ToArray();
    }

    public void Insert(User user)
    {
        entity.Add(user);
    }

    public User Get(int id)
    {
        return entity.Find(id)!;
    }

    public User GetByEmail(string email)
    {
        return entity.FirstOrDefault(x => x.Email == email)!;
    }
}
```

The preceding code explains everything regarding the unit of work. We have created an interface and created a class for each entity, like the user, and referenced it in the unit-of-work interface and class.

9. Config Your DB First Entity with IEntityTypeConfiguration interface

If you use the entity framework code first approach for your project, you should make some extra configurations for your entity. You can identify these configurations in several ways. But we generally use the IEntityTypeConfiguration interface in our project. This helps us to prepare our configuration and easily bind with our context object.

```c#
using CleanFunctionApp.Domain.Aggregation.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CleanFunctionApp.Infrastructure.Config;

public class UserConfig : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.HasIndex(x => x.Email).IsUnique();
    }
}
```

```c#
using CleanFunctionApp.Domain.Aggregation.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace CleanFunctionApp.Infrastructure;

public class Context : DbContext
{
    public Context(){}
    public Context(DbContextOptions<Context> options) : base(options)
    {
    }
    public Context(DbContextOptionsBuilder<Context> optionsBuilder) : base(optionsBuilder.Options)
    {
    }
    
    public DbSet<User>? Users { get; set; }
    
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            string conn = Configuration.AppSettings.GetConnectionString("DefaultConnection")!;
            optionsBuilder.UseSqlServer(conn);
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(Context).Assembly);
        base.OnModelCreating(modelBuilder);
    }
}
```

These two definitions describe the configuration of an entity. You can apply configuration to the context object, and when you migrate to a database, your database will be affected by these changes.

Summary

I have tried to explain clean architecture in Azure Function based on our experience in a previous project with my friend (Mucahit Furkan Ardogan). I highly recommend you use clean architecture and make everything simple for your project.

Repository: https://github.com/yusufsarikaya023/CleanFunctionApp
