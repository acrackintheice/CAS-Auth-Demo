package hello.model;

/**
 * Created by eduardo on 12/07/17.
 */
public class Greeting {

    String greet;

    public Greeting(String greet){
        this.greet = greet;
    }

    public String getGreet() {
        return greet;
    }

    public void setGreet(String greet) {
        this.greet = greet;
    }
}
