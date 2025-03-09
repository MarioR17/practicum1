package edu.iu.p466.prime_service.repository;

import edu.iu.p466.prime_service.model.Customer;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthenticationDBRepository
    extends CrudRepository<Customer, String>
{
    Customer findByUsername(String username);
}
