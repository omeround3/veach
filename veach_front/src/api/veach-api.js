import axios from "axios";
import Constants from "../utils/constants";

const API_ROOT_URL = Constants.API_ROOT_URL
const API_PORT = Constants.API_PORT

export default {
  login(username, password) {
    return axios
      .post(`${API_ROOT_URL}:${API_PORT}/api/login/`, {
        username: username,
        password: password,
      })
      .then((result) => result.data.token)
      .then((result) => {
        return result;
      })
      .catch((error) => {
        console.log(error);
        return error.response.status;
      });
  },
};
