package com.example.pillar

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@EnableScheduling
class PillarApplication

fun main(args: Array<String>) {
	runApplication<PillarApplication>(*args)
}