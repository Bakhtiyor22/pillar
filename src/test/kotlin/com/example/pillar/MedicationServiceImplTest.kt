package com.example.pillar

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.Mockito.*
import org.mockito.ArgumentMatchers.any
import org.springframework.data.domain.Page
import org.springframework.data.domain.PageImpl
import org.springframework.data.domain.PageRequest
import org.springframework.data.domain.Pageable
import java.time.LocalDate
import java.time.LocalTime
import java.util.Optional

class MedicationServiceImplTest {

    // Mock dependencies
    private lateinit var medicationRepository: MedicationRepository
    private lateinit var userRepository: UserRepository
    private lateinit var scheduleRepository: ScheduleRepository
    private lateinit var doctorRepository: DoctorRepository

    // System under test
    private lateinit var medicationService: MedicationServiceImpl

    @BeforeEach
    fun setUp() {
        medicationRepository = mock(MedicationRepository::class.java)
        userRepository = mock(UserRepository::class.java)
        scheduleRepository = mock(ScheduleRepository::class.java)
        doctorRepository = mock(DoctorRepository::class.java)

        medicationService = MedicationServiceImpl(
            medicationRepository,
            userRepository,
            scheduleRepository,
            doctorRepository
        )

        // Mock getCurrentUserId() method which is likely a protected or private method
        // This is a simplified approach - in a real test, you might use a spy or other techniques
        doReturn(1L).`when`(medicationService).getCurrentUserId()
    }

    // Tests for getAllMedications method

    @Test
    fun `getAllMedications should return page of medication DTOs`() {
        // Arrange
        val userId = 1L
        val pageable = PageRequest.of(0, 10)
        val user = createTestUser(userId)

        val medication1 = createTestMedication(1L, "Med 1", user)
        val medication2 = createTestMedication(2L, "Med 2", user)
        val medications = listOf(medication1, medication2)

        val page = PageImpl(medications, pageable, medications.size.toLong())

        `when`(medicationRepository.findByUserIdAndDeletedFalse(userId, pageable)).thenReturn(page)

        // Act
        val result = medicationService.getAllMedications(pageable)

        // Assert
        verify(medicationRepository).findByUserIdAndDeletedFalse(userId, pageable)
        assert(result.content.size == 2)
        assert(result.content[0].name == "Med 1")
        assert(result.content[1].name == "Med 2")
    }

    @Test
    fun `getAllMedications should return empty page when no medications exist`() {
        // Arrange
        val userId = 1L
        val pageable = PageRequest.of(0, 10)
        val emptyList = emptyList<Medication>()
        val emptyPage = PageImpl(emptyList, pageable, 0)

        `when`(medicationRepository.findByUserIdAndDeletedFalse(userId, pageable)).thenReturn(emptyPage)

        // Act
        val result = medicationService.getAllMedications(pageable)

        // Assert
        verify(medicationRepository).findByUserIdAndDeletedFalse(userId, pageable)
        assert(result.content.isEmpty())
    }

    @Test
    fun `getAllMedications should handle invalid pageable parameters`() {
        // Arrange
        val userId = 1L
        // Invalid page number (negative)
        val pageable = PageRequest.of(-1, 10)
        val emptyList = emptyList<Medication>()
        val emptyPage = PageImpl(emptyList, pageable, 0)

        `when`(medicationRepository.findByUserIdAndDeletedFalse(userId, pageable)).thenReturn(emptyPage)

        // Act
        val result = medicationService.getAllMedications(pageable)

        // Assert
        verify(medicationRepository).findByUserIdAndDeletedFalse(userId, pageable)
        assert(result.content.isEmpty())
    }

    // Tests for getMedicationById method

    @Test
    fun `getMedicationById should return medication DTO when found`() {
        // Arrange
        val userId = 1L
        val medicationId = 1L
        val user = createTestUser(userId)
        val medication = createTestMedication(medicationId, "Test Med", user)

        `when`(medicationRepository.findByIdAndUserIdAndDeletedFalse(medicationId, userId)).thenReturn(medication)

        // Act
        val result = medicationService.getMedicationById(medicationId)

        // Assert
        verify(medicationRepository).findByIdAndUserIdAndDeletedFalse(medicationId, userId)
        assert(result.id == medicationId)
        assert(result.name == "Test Med")
    }

    @Test
    fun `getMedicationById should throw exception when medication not found`() {
        // Arrange
        val userId = 1L
        val medicationId = 999L

        `when`(medicationRepository.findByIdAndUserIdAndDeletedFalse(medicationId, userId)).thenReturn(null)

        // Act & Assert
        assertThrows<ResourceNotFoundException> {
            medicationService.getMedicationById(medicationId)
        }

        verify(medicationRepository).findByIdAndUserIdAndDeletedFalse(medicationId, userId)
    }

    @Test
    fun `getMedicationById should throw exception when medication belongs to another user`() {
        // Arrange
        val userId = 1L
        val otherUserId = 2L
        val medicationId = 1L
        val otherUser = createTestUser(otherUserId)
        val medication = createTestMedication(medicationId, "Other User Med", otherUser)

        `when`(medicationRepository.findByIdAndUserIdAndDeletedFalse(medicationId, userId)).thenReturn(null)

        // Act & Assert
        assertThrows<ResourceNotFoundException> {
            medicationService.getMedicationById(medicationId)
        }

        verify(medicationRepository).findByIdAndUserIdAndDeletedFalse(medicationId, userId)
    }

    // Tests for createMedication method

    @Test
    fun `createMedication should create and return medication DTO`() {
        // Arrange
        val userId = 1L
        val user = createTestUser(userId)

        val request = createMedicationRequest(
            name = "New Med",
            medType = MedType.PRESCRIPTION,
            dose = 10.0,
            pillType = PillType.TABLET,
            startDate = LocalDate.now(),
            endDate = LocalDate.now().plusDays(30)
        )

        val savedMedication = createTestMedication(1L, request.name, user)
        val schedule = Schedule(
            frequencyType = FrequencyType.DAILY,
            timeOfDay = LocalTime.of(8, 0),
            medication = savedMedication,
            pillsPerDose = 1,
            isActive = true,
            takenLogs = mutableSetOf()
        )
        savedMedication.schedules.add(schedule)

        `when`(userRepository.findByIdAndDeletedFalse(userId)).thenReturn(user)
        `when`(medicationRepository.save(any())).thenReturn(savedMedication)
        `when`(scheduleRepository.save(any())).thenReturn(schedule)
        `when`(medicationRepository.findById(savedMedication.id!!)).thenReturn(Optional.of(savedMedication))

        // Act
        val result = medicationService.createMedication(request)

        // Assert
        verify(userRepository).findByIdAndDeletedFalse(userId)
        verify(medicationRepository, times(2)).save(any())
        verify(medicationRepository).findById(savedMedication.id!!)

        assert(result.name == request.name)
        assert(result.dosage == request.dose.toString())
        assert(result.form == request.pillType)
    }

    @Test
    fun `createMedication should throw exception when user not found`() {
        // Arrange
        val userId = 1L

        val request = createMedicationRequest(
            name = "New Med",
            medType = MedType.PROCEDURES,
            dose = 1,
            pillType = PillType.TABLETS,
            startDate = LocalDate.now(),
            endDate = LocalDate.now().plusDays(30)
        )

        `when`(userRepository.findByIdAndDeletedFalse(userId)).thenReturn(null)

        // Act & Assert
        assertThrows<UserNotFoundException> {
            medicationService.createMedication(request)
        }

        verify(userRepository).findByIdAndDeletedFalse(userId)
        verify(medicationRepository, never()).save(any())
    }

    @Test
    fun `createMedication should handle null optional fields`() {
        // Arrange
        val userId = 1L
        val user = createTestUser(userId)

        val request = createMedicationRequest(
            name = "New Med",
            medType = MedType.PRESCRIPTION,
            dose = 10.0,
            pillType = PillType.TABLET,
            startDate = LocalDate.now(),
            endDate = LocalDate.now().plusDays(30),
            // All optional fields are null
            foodInstruction = null,
            initialPillCount = null,
            refillThreshold = null,
            isActive = null,
            instructions = null,
            frequencyType = null,
            times = null,
            pillsPerDose = null,
            specificDaysOfWeek = null,
            intervalDays = null,
            doctorId = null
        )

        val savedMedication = createTestMedication(1L, request.name, user)

        `when`(userRepository.findByIdAndDeletedFalse(userId)).thenReturn(user)
        `when`(medicationRepository.save(any())).thenReturn(savedMedication)
        `when`(medicationRepository.findById(savedMedication.id!!)).thenReturn(Optional.of(savedMedication))

        // Act
        val result = medicationService.createMedication(request)

        // Assert
        verify(userRepository).findByIdAndDeletedFalse(userId)
        verify(medicationRepository, times(2)).save(any())
        verify(medicationRepository).findById(savedMedication.id!!)

        assert(result.name == request.name)
    }

    // Tests for updateMedication method

    @Test
    fun `updateMedication should update and return medication DTO`() {
        // Arrange
        val userId = 1L
        val medicationId = 1L
        val user = createTestUser(userId)
        val existingMedication = createTestMedication(medicationId, "Old Name", user)

        val request = updateMedicationRequest(
            name = "Updated Name",
            dosage = "20.0",
            form = PillType.CAPSULE,
            startDate = LocalDate.now(),
            endDate = LocalDate.now().plusDays(60)
        )

        val updatedMedication = createTestMedication(medicationId, request.name!!, user)
        updatedMedication.dose = request.dosage!!.toDouble()
        updatedMedication.pillType = request.form!!

        `when`(medicationRepository.findByIdAndUserIdAndDeletedFalse(medicationId, userId)).thenReturn(existingMedication)
        `when`(medicationRepository.save(any())).thenReturn(updatedMedication)
        `when`(medicationRepository.findById(medicationId)).thenReturn(Optional.of(updatedMedication))

        // Act
        val result = medicationService.updateMedication(medicationId, request)

        // Assert
        verify(medicationRepository).findByIdAndUserIdAndDeletedFalse(medicationId, userId)
        verify(medicationRepository, times(2)).save(any())
        verify(medicationRepository).findById(medicationId)

        assert(result.name == request.name)
        assert(result.dosage == request.dosage)
        assert(result.form == request.form)
    }

    @Test
    fun `updateMedication should throw exception when medication not found`() {
        // Arrange
        val userId = 1L
        val medicationId = 999L

        val request = updateMedicationRequest(
            name = "Updated Name",
            startDate = LocalDate.now(),
            endDate = LocalDate.now().plusDays(60)
        )

        `when`(medicationRepository.findByIdAndUserIdAndDeletedFalse(medicationId, userId)).thenReturn(null)

        // Act & Assert
        assertThrows<ResourceNotFoundException> {
            medicationService.updateMedication(medicationId, request)
        }

        verify(medicationRepository).findByIdAndUserIdAndDeletedFalse(medicationId, userId)
        verify(medicationRepository, never()).save(any())
    }

    @Test
    fun `updateMedication should handle partial updates with null fields`() {
        // Arrange
        val userId = 1L
        val medicationId = 1L
        val user = createTestUser(userId)
        val existingMedication = createTestMedication(medicationId, "Old Name", user)

        // Only updating the name, leaving other fields null
        val request = updateMedicationRequest(
            name = "Updated Name",
            dosage = null,
            form = null,
            startDate = LocalDate.now(),
            endDate = LocalDate.now().plusDays(60)
        )

        val updatedMedication = createTestMedication(medicationId, request.name!!, user)

        `when`(medicationRepository.findByIdAndUserIdAndDeletedFalse(medicationId, userId)).thenReturn(existingMedication)
        `when`(medicationRepository.save(any())).thenReturn(updatedMedication)
        `when`(medicationRepository.findById(medicationId)).thenReturn(Optional.of(updatedMedication))

        // Act
        val result = medicationService.updateMedication(medicationId, request)

        // Assert
        verify(medicationRepository).findByIdAndUserIdAndDeletedFalse(medicationId, userId)
        verify(medicationRepository, times(2)).save(any())
        verify(medicationRepository).findById(medicationId)

        assert(result.name == request.name)
    }

    // Tests for deleteMedication method

    @Test
    fun `deleteMedication should soft delete medication`() {
        // Arrange
        val userId = 1L
        val medicationId = 1L
        val user = createTestUser(userId)
        val medication = createTestMedication(medicationId, "Test Med", user)

        `when`(medicationRepository.findByIdAndUserIdAndDeletedFalse(medicationId, userId)).thenReturn(medication)

        // Act
        medicationService.deleteMedication(medicationId)

        // Assert
        verify(medicationRepository).findByIdAndUserIdAndDeletedFalse(medicationId, userId)
        verify(medicationRepository).trash(medicationId)
        verify(scheduleRepository).deleteByMedicationId(medicationId)
    }

    @Test
    fun `deleteMedication should throw exception when medication not found`() {
        // Arrange
        val userId = 1L
        val medicationId = 999L

        `when`(medicationRepository.findByIdAndUserIdAndDeletedFalse(medicationId, userId)).thenReturn(null)

        // Act & Assert
        assertThrows<ResourceNotFoundException> {
            medicationService.deleteMedication(medicationId)
        }

        verify(medicationRepository).findByIdAndUserIdAndDeletedFalse(medicationId, userId)
        verify(medicationRepository, never()).trash(medicationId)
        verify(scheduleRepository, never()).deleteByMedicationId(medicationId)
    }

    @Test
    fun `deleteMedication should handle security implications by checking user ownership`() {
        // Arrange
        val userId = 1L
        val otherUserId = 2L
        val medicationId = 1L
        val otherUser = createTestUser(otherUserId)
        val medication = createTestMedication(medicationId, "Other User Med", otherUser)

        `when`(medicationRepository.findByIdAndUserIdAndDeletedFalse(medicationId, userId)).thenReturn(null)

        // Act & Assert
        assertThrows<ResourceNotFoundException> {
            medicationService.deleteMedication(medicationId)
        }

        verify(medicationRepository).findByIdAndUserIdAndDeletedFalse(medicationId, userId)
        verify(medicationRepository, never()).trash(medicationId)
        verify(scheduleRepository, never()).deleteByMedicationId(medicationId)
    }

    // Helper methods to create test objects

    private fun createTestUser(id: Long): User {
        val user = User(
            firstName = "Test",
            lastName = "User",
            email = "test$id@example.com",
            password = "password",
            role = Roles.CUSTOMER
        )
        user.id = id
        return user
    }

    private fun createTestMedication(id: Long, name: String, user: User): Medication {
        val medication = Medication(
            pillName = name,
            medType = MedType.PRESCRIPTION,
            dose = 10.0,
            pillType = PillType.TABLET,
            foodInstruction = FoodInstruction.ANY_TIME,
            comment = "Test comment",
            initialPillCount = 30,
            currentPillCount = 30,
            refillThreshold = 10,
            isActive = true,
            startDate = LocalDate.now(),
            endDate = LocalDate.now().plusDays(30),
            user = user,
            doctor = null,
            schedules = mutableSetOf()
        )
        medication.id = id
        return medication
    }
}