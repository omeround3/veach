import { createStore } from "vuex";

export default createStore({
  state() {
    return {
      username: null,
      password: null,
      token: null,
    };
  },
  getters: {
    getUsername: (state) => state.username,
    getPassword: (state) => state.password,
    getToken: (state) => state.token,
    isLoggedIn: (state) => !!state.token,
  },
  mutations: {
    setUser(state, value) {
      state.username = value == null ? null : value;
    },
    setPassword(state, value) {
      state.password = value == null ? null : value;
    },
    setToken(state, value) {
      state.token = value == null ? null : value;
    },
  },
  actions: {
    logout: ({ commit }) => {
      commit("setToken", null);
      // setTimeout(() => router.push("/sign-in"), 500);
    },
    login({ commit }, { username, password, token }) {
      if (token != "null") {
        commit("setUser", username);
        commit("setPassword", password);
        commit("setToken", token);
        window.localStorage.setItem("username", username);
        window.localStorage.setItem("password", password);
        window.localStorage.setItem("token", token);
        // setting timeout for the store to be completed 500 milliseconds in order for user details to load before redirecting to main dashboard
        // setTimeout(() => router.push("/"), 500);
      }
    },
  },
});
