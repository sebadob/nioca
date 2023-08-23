<script>
	import { base } from "$app/paths";
	const url = `${base}/logo-main.png`;
</script>

<div class="container">
  <img src={url} alt="Main Logo" class="logo"/>
</div>

<style>
  .container {
      position: absolute;
      top: 0;
      left: 0;
      padding: 15px;
  }

  .logo {
      width: 170px;
  }
</style>
