package edu.iu.p466.prime_service.service;

import edu.iu.p466.prime_service.model.Customer;
import java.io.IOException;

public interface IAuthenticationService {
    Customer register(Customer customer) throws IOException;
    //boolean login(String username, String password) throws IOException;
}
