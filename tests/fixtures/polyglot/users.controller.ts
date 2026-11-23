import { Controller, Get, UseGuards } from "@nestjs/common";

@Controller("users")
export class UsersController {
  constructor(private readonly svc: UsersService) {}

  @Get(":id")
  @UseGuards(AuthGuard)
  findOne(id: string) {
    return this.svc.findUser(id);
  }
}
