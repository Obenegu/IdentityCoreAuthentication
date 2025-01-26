using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace UerAuth_Auth.Migrations
{
    /// <inheritdoc />
    public partial class SecondMigration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "0a161597-e122-4b87-85ac-2a17882ff112");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "3b59a5a6-c30a-4d9b-8015-3a9fd5b7e7d2");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "6fa26e89-dd4a-4820-bd02-fc657a4910ff");

            migrationBuilder.CreateTable(
                name: "Todos",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Title = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    isCompleted = table.Column<bool>(type: "bit", nullable: false),
                    IdentityUserId = table.Column<string>(type: "nvarchar(450)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Todos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Todos_AspNetUsers_IdentityUserId",
                        column: x => x.IdentityUserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id");
                });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "0f92b17f-7902-4109-9da9-e650f97a542e", "2", "User", "User" },
                    { "3cf4e0a3-12a5-48f3-8989-06ddeae9c5c5", "1", "Admin", "Admin" },
                    { "6a474702-59c7-47f9-9b2b-f668a779c4a6", "3", "HR", "HR" }
                });

            migrationBuilder.CreateIndex(
                name: "IX_Todos_IdentityUserId",
                table: "Todos",
                column: "IdentityUserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Todos");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "0f92b17f-7902-4109-9da9-e650f97a542e");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "3cf4e0a3-12a5-48f3-8989-06ddeae9c5c5");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "6a474702-59c7-47f9-9b2b-f668a779c4a6");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "0a161597-e122-4b87-85ac-2a17882ff112", "2", "User", "User" },
                    { "3b59a5a6-c30a-4d9b-8015-3a9fd5b7e7d2", "3", "HR", "HR" },
                    { "6fa26e89-dd4a-4820-bd02-fc657a4910ff", "1", "Admin", "Admin" }
                });
        }
    }
}
