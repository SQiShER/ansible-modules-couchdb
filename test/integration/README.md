# Development
## Running the tests
The environment used to execute the test suite is composed via Docker containers. In order to execute the tests, please use `docker-compose` from the [Docker Toolbox](https://www.docker.com/docker-toolbox):

```bash
# Initially
docker-compose up -d

# Execute the tests, make changes, rinse and repeat
docker-compose run --rm tests ansible-playbook -i inventory playbook.yml

# Cleanup once you're done
docker-compose stop
docker-compose rm -f
```
