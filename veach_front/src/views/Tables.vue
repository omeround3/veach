<template>
  <div class="container-fluid py-4">
    <div class="row">
      <div class="col-12">
        <div class="card my-4">
          <div class="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
            <div class="bg-gradient-success shadow-warning border-radius-lg pt-4 pb-3">
              <h6 class="text-white text-capitalize ps-3">{{ tag }}</h6>
            </div>
          </div>
          <div class="card-body px-0 pb-2">
            <div class="table-responsive p-0">
              <table class="table align-items-center justify-content-center mb-0">
                <thead>
                  <tr>
                    <th class="text-uppercase text-secondary text-xxs font-weight-bolder opacity-7">
                      Product
                    </th>
                    <th class="text-uppercase text-secondary text-xxs font-weight-bolder opacity-7">
                      Version
                    </th>
                    <th class="text-uppercase text-secondary text-xxs font-weight-bolder opacity-7">
                      CVE
                    </th>
                    <th class="text-uppercase text-secondary text-xxs font-weight-bolder opacity-7">
                      Score
                    </th>
                    <th class="text-uppercase text-secondary text-xxs font-weight-bolder opacity-7">
                      Mitigation
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(
                {
                product,
                version,
                cve_id,
                score,
                mitigation
              },
                index
              ) of cves" :key="index">
                    <td>
                      <div class="d-flex px-3">
                        <h6 class="mb-0 text-sm">{{ product }}</h6>
                      </div>
                    </td>
                    <td>
                      <div class="d-flex px-3">
                        <h6 class="mb-0 text-sm">{{ version }}</h6>
                      </div>
                    </td>
                    <td>
                      <div class="d-flex px-3">
                        <h6 class="mb-0 text-sm">{{ cve_id }}</h6>
                      </div>
                    </td>
                    <td>
                      <div class="d-flex px-3">
                        <h6 class="mb-0 text-sm">{{ score }}</h6>
                      </div>
                    </td>
                    <td>
                      <div class="d-flex px-3">
                        <h6 class="mb-0 text-sm">{{ mitigation }}</h6>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "tables",
  props: {
    tag: {
      type: String,
      default: "",
    },
    cves: {
      type: Array,
      required: true,
    },
  },
};
</script>
