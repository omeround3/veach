import axios from "axios";
import { API_ROOT_URL } from "@utils/api";

export default {
  login(username, password) {
    return axios
      .post(`${API_ROOT_URL}/api/login/`, {
        username: username,
        password: password,
      })
      .then((result) => result.data.token)
      .then((result) => {
        console.log(`token is ${token}`);
        return result;
      })
      .catch((error) => {
        console.log(error);
        return error.response.status;
      });
  },
};
