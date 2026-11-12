package demo;

@RestController
@RequestMapping("/api")
public class UserController {
    private final UserRepository repo;

    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public User show(@PathVariable String id) {
        // repo.findUser(id) in a comment is not a call
        return repo.findUser(id);
    }
}
