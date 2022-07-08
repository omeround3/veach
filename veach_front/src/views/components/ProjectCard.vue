<template>
  <div class="card">
    <div class="card-header pb-0">
      <div class="row">
        <div class="col-lg-6 col-7">
          <h6>{{ title }}</h6>
          <p class="text-sm mb-0" v-html="description"></p>
        </div>
      </div>
    </div>
    <div class="card-body px-0 pb-2">
      <div class="table-responsive">
        <table class="table align-items-center mb-0">
          <thead>
            <tr>
              <th v-for="(heading, index) of headers" :key="index"
                class="text-uppercase text-secondary text-xxs font-weight-bolder opacity-7"
                style="white-space: pre-wrap;">
                {{ heading }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr :class="[critical ? 'table-danger' : '']" v-for="(
                {
                vector,
                complexity,
                score,
                confidentiality,
                integrity,
                availability,
                size,
                critical,
                string
              },
                index
              ) of projects" :key="index" @click="goTo(string)">
              <td>
                <div class="d-flex ps-3 py-1">
                  <div class="d-flex flex-column justify-content-center">
                    <h6 class="mb-0 text-sm">{{ vector }}</h6>
                  </div>
                </div>
              </td>
              <td>
                <div class="d-flex ps-3 py-1">
                  <div class="d-flex flex-column justify-content-center">
                    <h6 class="mb-0 text-sm">{{ complexity }}</h6>
                  </div>
                </div>
              </td>
              <td>
                <div class="d-flex ps-3 py-1">
                  <div class="d-flex flex-column justify-content-center">
                    <h6 class="mb-0 text-sm">{{ confidentiality }}</h6>
                  </div>
                </div>
              </td>
              <td>
                <div class="d-flex ps-3 py-1">
                  <div class="d-flex flex-column justify-content-center">
                    <h6 class="mb-0 text-sm">{{ integrity }}</h6>
                  </div>
                </div>
              </td>
              <td>
                <div class="d-flex ps-3 py-1">
                  <div class="d-flex flex-column justify-content-center">
                    <h6 class="mb-0 text-sm">{{ availability }}</h6>
                  </div>
                </div>
              </td>
              <td>
                <div class="d-flex ps-3 py-1">
                  <div class="d-flex flex-column justify-content-center">
                    <h6 class="mb-0 text-sm">{{ score }}</h6>
                  </div>
                </div>
              </td>
              <td>
                <div class="d-flex ps-3 py-1">
                  <div class="d-flex flex-column justify-content-center">
                    <h6 class="mb-0 text-sm">{{ size }}</h6>
                  </div>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "projectCard",
  props: {
    title: {
      type: String,
      default: "",
    },
    description: {
      type: String,
      default: "",
    },
    headers: {
      type: Array,
      required: true,
    },
    projects: {
      vector: String,
      complexity: String,
      score: Number,
      size: Number,
      confidentiality: String,
      integrity: String,
      availability: String,
      critical: Boolean
    }
  },
  methods: {
    goTo(string) {
      this.$router.push('/' + string)
    }
  }
};
</script>
