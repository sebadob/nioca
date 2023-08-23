<script>
	import IconChevronRight from "./icons/IconChevronRight.svelte";
	import { slide } from 'svelte/transition';
	import { spring } from "svelte/motion";

	export let show = false;
	let isHover = false;

	const rotate = spring(0, {
		stiffness: 0.1,
		damping: 0.4
	});

	function toggle() {
		show = !show;
		if (show) {
      rotate.set(90);
    } else {
			rotate.set(0);
    }
  }
</script>

<div
    class="container"
    style="border-left: {show ? '1px solid var(--col-ok)' : '1px solid var(--col-inact)'}"
>
  <div class="containerHeader">
    <div
        class="expand"
        on:mouseenter={() => isHover = true}
        on:mouseleave={() => isHover = false}
        on:click={toggle}
        on:keypress={toggle}
    >
      <div style="rotate: {$rotate}deg">
        <IconChevronRight
            color={isHover ? 'var(--col-err)'
            : show ? 'var(--col-ok)' : 'var(--col-text)'}
        />
      </div>
    </div>

    <div class="header">
      <slot name="header"></slot>
    </div>
  </div>

  {#if show}
    <div class="containerBody" transition:slide|global={{ duration: 200 }}>
        <div class="body">
          <slot name="body"></slot>
        </div>
    </div>
  {/if}
</div>

<style>
    .container {
        display: flex;
        flex-direction: column;
        width: 100%;
        max-width: 1600px;
    }

    .containerHeader {
        display: flex;
        padding: 5px 7px;
        border: 1px solid var(--col-inact);
        border-left: none;
    }

    .containerBody {
        border-bottom: 1px solid var(--col-acnt);
        border-right: 1px solid var(--col-inact);
    }

    .expand {
        display: flex;
        align-items: center;
        padding-top: 2px;
        cursor: pointer;
    }

    .header {
        margin: 3px;
        display: flex;
    }

    .body {
        overflow: hidden;
        overflow-y: auto;
    }
</style>
