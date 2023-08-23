<script>
  import { spring } from "svelte/motion";

  export let selected = false;
	const selMargin = 11;

  let margin = spring(0, {
	  stiffness: 0.15,
	  damping: 0.5
  });

	$: margin.set(selected ? selMargin : 0);

	function handleClick() {
		selected = !selected;
  }
</script>

<div
    class="outer"
    class:selectedOuter={selected}
    on:click={handleClick}
    on:keypress={handleClick}
>
  <div class="inner" class:selected style="margin-left: {`${$margin}px`}">
  </div>
</div>

<style>
  .outer {
      display: flex;
      justify-content: flex-start;
      align-items: center;
      padding: 3px;
      height: 20px;
      width: 33px;
      border: 1px solid var(--col-acnt);
      background: var(--col-inact);
      border-radius: 10px;
      cursor: pointer;
      box-shadow: inset 0 0 3px rgba(0, 0, 0, 0.15);
  }

  .selectedOuter {
      background: var(--col-ok);
  }

  .inner {
      height: 14px;
      width: 14px;
      border-radius: 50%;
      background: var(--col-err);
  }

  .selected {
      background: var(--col-text);
  }
</style>
