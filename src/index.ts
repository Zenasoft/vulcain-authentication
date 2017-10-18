import { Application } from 'vulcain-corejs';
// Enable basic authentication
import './api/basicAuthentication';


let srv = new Application('Users');
srv.start(8080);