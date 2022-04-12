package io.jzheaux.springsecurity.resolutions;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.naming.AuthenticationException;
import javax.transaction.Transactional;
import java.util.Optional;
import java.util.UUID;

@RestController
public class ResolutionController {
	private final ResolutionRepository resolutions;
	private final UserRepository users;

	public ResolutionController(ResolutionRepository resolutions, UserRepository users) {
		this.resolutions = resolutions;
		this.users = users;
	}

	@CrossOrigin(allowCredentials = "true")
	@GetMapping("/resolutions")
	@PreAuthorize("hasAuthority('resolution:read', 'SCOPE_resolution:read')")
	@PostFilter("filterObject.owner == authentication.name || hasRole('ADMIN')")
	public Iterable<Resolution> read() {
		Iterable<Resolution>  resolutions =this.resolutions.findAll();
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication.getAuthorities().contains(new SimpleGrantedAuthority("user:read"))) {

			for (Resolution resolution : resolutions) {
				String fullName = this.users.findByUsername(resolution.getOwner())
						.map(User::getFullName).orElse("Anonymous");
				resolution.setText(resolution.getText() + ", by " + fullName);
			}
		}
		return resolutions;
	}

	@GetMapping("/resolution/{id}")
	@PostAuthorize("returnObject.orElse(null)?.owner == authentication.name || hasRole('ADMIN')")
	public Optional<Resolution> read(@PathVariable("id") UUID id) {
		return this.resolutions.findById(id);
	}

	@PostMapping("/resolution")
	@PreAuthorize("hasAuthority('resolution:read')")
	public Resolution make(@CurrentUsername String owner, @RequestBody String text) {
		//String owner = "user";
		Resolution resolution = new Resolution(text, owner);
		return this.resolutions.save(resolution);
	}

	@PutMapping(path="/resolution/{id}/revise")
	@Transactional
	@PreAuthorize("hasAuthority('resolution:write')")
	//@PostAuthorize("returnObject.orElse(null)?.owner == authentication.name")
	@PostAuthorize("@post.authorize(#root)")
	public Optional<Resolution> revise(@PathVariable("id") UUID id, @RequestBody String text) {
		this.resolutions.revise(id, text);
		return read(id);
	}

	@PutMapping("/resolution/{id}/complete")
	@Transactional
	@PreAuthorize("hasAuthority('resolution:write')")
	//@PostAuthorize("returnObject.orElse(null)?.owner == authentication.name")
	@PostAuthorize("@post.authorize(#root)")
	public Optional<Resolution> complete(@PathVariable("id") UUID id) {
		this.resolutions.complete(id);
		return read(id);
	}



}
